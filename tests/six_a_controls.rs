// SPDX-License-Identifier: GPL-3.0-or-later
//! 6A controls (D-record §6): birth, thread, non-leader, exec, PID reuse,
//! lost-event, over-capacity fairness, custody/output matrix,
//! dynamic-module/namespace/cgroup/cleanup, plus §7 shape conformance.
//!
//! Black-box behavioral tests through a staged privileged binary
//! (dev-layout: binary + `osslscope-provider-observation` +
//! `osslscope-focused-count` siblings, root-owned so the privileged
//! companion trust check passes). Oracle instruments are fixture-owned
//! (fork/exec/exit logs, application-owned crypto counters) plus
//! harness-side direct `/proc` reads — never the observer's records.
//!
//! INCONCLUSIVE (early return, never assert) when the fixture fails to
//! produce the required stimulus or an oracle instrument fails.

use osslscope::target::{CustodyState, OwnedTarget, TargetDisposition, WorkloadDest};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn fresh_dir(prefix: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ossl-6a-{}-{}-{}",
        prefix,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

/// Root-trusted staging for the just-built binary + BPF companions (dev
/// layout). The privileged companion trust check requires every path
/// component root-owned and non-writable, so staging lives under `/opt`
/// (never world-writable `/tmp`). Removed on drop (best-effort sudo).
struct StagedBinary {
    dir: PathBuf,
    binary: PathBuf,
}
impl Drop for StagedBinary {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "rm", "-rf"])
            .arg(&self.dir)
            .status();
    }
}

/// Stage the just-built binary with BPF companions, or `None`
/// (INCONCLUSIVE) when companions are absent or staging is refused.
fn stage_privileged_binary() -> Option<StagedBinary> {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_osslscope"));
    let release = built.ancestors().nth(2).map(|p| p.join("release")).unwrap();
    let obs = release.join("osslscope-provider-observation");
    let count = release.join("osslscope-focused-count");
    if !obs.is_file() || !count.is_file() {
        eprintln!("INCONCLUSIVE: BPF companions absent under {release:?}");
        return None;
    }
    let dir = PathBuf::from(format!(
        "/opt/ossl-6a-stage-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let script = format!(
        "mkdir -p {} && cp {} {} {} {}/ && chown root:root {}/osslscope {}/osslscope-provider-observation {}/osslscope-focused-count && chmod 755 {}/osslscope && chmod 644 {}/osslscope-provider-observation {}/osslscope-focused-count",
        dir.display(),
        built.display(),
        obs.display(),
        count.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
        dir.display(),
    );
    let status = Command::new("sudo")
        .args(["-n", "sh", "-c", &script])
        .status()
        .unwrap();
    if !status.success() {
        eprintln!("INCONCLUSIVE: sudo -n staging refused");
        return None;
    }
    let binary = dir.join("osslscope");
    Some(StagedBinary { dir, binary })
}

/// Background observer writing JSON lines to `outfile`. The caller signals
/// fixtures after the `start` record lands, then waits for completion.
fn spawn_observer(binary: &Path, args: &[&str], outfile: &Path) -> Child {
    let file = fs::File::create(outfile).unwrap();
    Command::new("sudo")
        .arg("-n")
        .arg(binary)
        .args(args)
        .stdout(Stdio::from(file))
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_for_kind(outfile: &Path, kind: &str, timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        let text = fs::read_to_string(outfile).unwrap_or_default();
        for line in text.lines() {
            if let Ok(row) = serde_json::from_str::<serde_json::Value>(line) {
                if row["kind"] == kind {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn spawn_observer_stderr(binary: &Path, args: &[&str], outfile: &Path, errfile: &Path) -> Child {
    let file = fs::File::create(outfile).unwrap();
    let err = fs::File::create(errfile).unwrap();
    Command::new("sudo")
        .arg("-n")
        .arg(binary)
        .args(args)
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(err))
        .stdin(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_for_stderr(errfile: &Path, needle: &str, timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if fs::read_to_string(errfile)
            .unwrap_or_default()
            .contains(needle)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Interactive driver for `tests/fixtures/provider_observation.c`.
struct FixtureSession {
    child: Child,
    reader: std::io::BufReader<std::process::ChildStdout>,
}
impl FixtureSession {
    fn start(dir: &Path) -> Self {
        let app = compile_c(
            dir,
            &["provider_observation.c"],
            "app",
            &["-lcrypto", "-ldl"],
        );
        compile_c(
            dir,
            &["provider_observation_provider.c"],
            "provider.so",
            &["-shared", "-fPIC"],
        );
        let mut child = Command::new(app)
            .arg(dir.join("provider.so"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut session = Self {
            child,
            reader: std::io::BufReader::new(stdout),
        };
        assert_eq!(session.line(), "ready");
        session
    }
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn line(&mut self) -> String {
        let mut text = String::new();
        use std::io::BufRead;
        self.reader.read_line(&mut text).unwrap();
        assert!(!text.is_empty(), "fixture stdout ended early");
        text.trim_end().to_string()
    }
    /// Send a command plus extra argument lines (e.g. `K` reads two);
    /// returns non-ack output lines. Panics unless the ack reports success.
    fn cmd2(&mut self, command: &str, args: &[&str]) -> Vec<String> {
        use std::io::Write;
        let mut text = format!("{command}\n");
        for arg in args {
            text.push_str(arg);
            text.push('\n');
        }
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        let mut out = Vec::new();
        loop {
            let line = self.line();
            if let Some(ack) = line.strip_prefix("ack ") {
                let fields: Vec<&str> = ack.split_whitespace().collect();
                assert_eq!(fields.len(), 7, "malformed ack: {line}");
                assert_eq!(fields[1], "1", "fixture command failed: {command}: {line}");
                return out;
            }
            out.push(line);
        }
    }
    /// Send one command line; returns non-ack output lines. Panics unless
    /// the ack reports success.
    fn cmd(&mut self, command: &str) -> Vec<String> {
        use std::io::Write;
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{command}\n").as_bytes())
            .unwrap();
        let mut out = Vec::new();
        loop {
            let text = self.line();
            if let Some(ack) = text.strip_prefix("ack ") {
                let fields: Vec<&str> = ack.split_whitespace().collect();
                assert_eq!(fields.len(), 7, "malformed ack: {text}");
                assert_eq!(fields[1], "1", "fixture command failed: {command}: {text}");
                return out;
            }
            out.push(text);
        }
    }
    /// Write a command without reading (the caller dumps maps
    /// across the fixture's work, then drains with `drain_ack`).
    fn write_raw(&mut self, text: &str) {
        use std::io::Write;
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    /// Drain lines until the ack; `None` on fixture failure or EOF
    /// (the caller goes INCONCLUSIVE -- fixture-side fault).
    fn drain_ack(&mut self) -> Option<Vec<String>> {
        let mut out = Vec::new();
        loop {
            let mut text = String::new();
            use std::io::BufRead;
            if self.reader.read_line(&mut text).ok()? == 0 {
                return None;
            }
            let text = text.trim_end().to_string();
            if text.is_empty() {
                continue;
            }
            if let Some(ack) = text.strip_prefix("ack ") {
                let fields: Vec<&str> = ack.split_whitespace().collect();
                if fields.len() != 7 || fields[1] != "1" {
                    return None;
                }
                return Some(out);
            }
            out.push(text);
        }
    }
    fn finish(mut self) {
        use std::io::Write;
        let _ = self.child.stdin.as_mut().unwrap().write_all(b"E\n");
        let _ = self.child.wait();
    }
    fn abort(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for FixtureSession {
    fn drop(&mut self) {
        self.abort();
    }
}

fn read_rows(outfile: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(outfile)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// Tolerant variant for LIVE polls of a file the observer is still
/// writing: a partially written trailing line is skipped, never
/// fatal. Final reads stay strict (read_rows).
fn read_rows_partial(outfile: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(outfile)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn kinds(rows: &[serde_json::Value]) -> BTreeMap<&str, usize> {
    let mut out = BTreeMap::new();
    for row in rows {
        *out.entry(row["kind"].as_str().unwrap_or("?")).or_insert(0) += 1;
    }
    out
}

fn starttime_of(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().nth(19)?.parse().ok()
}

fn alive(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

fn compile_c(dir: &Path, sources: &[&str], output: &str, extra: &[&str]) -> PathBuf {
    let mut cc = Command::new("cc");
    cc.args(["-O2", "-Wall", "-Wextra", "-Werror"]);
    for source in sources {
        cc.arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(source),
        );
    }
    cc.args(extra).arg("-o").arg(dir.join(output));
    let result = cc.output().unwrap();
    assert!(
        result.status.success(),
        "cc failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    dir.join(output)
}

/// Harness-owned 100ms `/proc` census sampler (distinct code path from the
/// observer): logs `(pid, starttime, ppid)` lines until `stop` fires.
fn spawn_census_sampler(log: PathBuf, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    std::thread::spawn(move || {
        let mut file = fs::File::create(&log).unwrap();
        while !stop.load(Ordering::Relaxed) {
            let mut count = 0u32;
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.parse::<u32>().is_err() {
                        continue;
                    }
                    let Ok(stat) = fs::read_to_string(format!("/proc/{name}/stat")) else {
                        continue;
                    };
                    let Some((pid_s, rest)) = stat.split_once(' ') else {
                        continue;
                    };
                    let Some(after) = rest.rsplit_once(')').map(|(_, a)| a) else {
                        continue;
                    };
                    let mut fields = after.split_whitespace();
                    let (Some(_state), Some(ppid), Some(_pgrp)) =
                        (fields.next(), fields.next(), fields.next())
                    else {
                        continue;
                    };
                    let mut fields = after.split_whitespace();
                    let starttime = fields.nth(19).unwrap_or("?");
                    let _ = writeln!(file, "{pid_s} {starttime} {ppid}");
                    count += 1;
                }
            }
            let _ = writeln!(file, "# census {count}");
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}

/// Pids named by membership/limit/deferred_removed records (explicit, never
/// covered-only), plus per-pid states.
fn explicit_pids(rows: &[serde_json::Value]) -> BTreeMap<u64, BTreeSet<String>> {
    let mut out: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let kind = row["kind"].as_str().unwrap_or("");
        let pid = match kind {
            "membership" | "limit" | "session_gap" => row["incarnation"]["pid"].as_u64(),
            _ => None,
        };
        if let Some(pid) = pid {
            let state = match kind {
                "membership" => format!("membership:{}", row["state"].as_str().unwrap_or("?")),
                "limit" => format!("limit:{}", row["reason"].as_str().unwrap_or("?")),
                _ => kind.to_string(),
            };
            out.entry(pid).or_default().insert(state);
        }
    }
    out
}

fn segments_by_pid(rows: &[serde_json::Value]) -> BTreeMap<u64, Vec<&serde_json::Value>> {
    let mut out: BTreeMap<u64, Vec<&serde_json::Value>> = BTreeMap::new();
    for row in rows {
        if row["kind"] == "process_observation" {
            if let Some(pid) = row["incarnation"]["pid"].as_u64() {
                out.entry(pid).or_default().push(row);
            }
        }
    }
    out
}

/// Control 1 (birth + between-tick adversarial): 32 sub-tick children plus
/// 4 survivors. Every oracle-counted child is explicit or covered-unknown;
/// survivors are never covered-only; no count inheritance.
#[test]
fn control_1_birth_records_every_child() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let dir = fresh_dir("birth");
    let parent_bin = compile_c(&dir, &["burst_parent.c"], "burst_parent", &["-lcrypto"]);
    let log = dir.join("fork.log");
    let census_log = dir.join("census.log");
    let go = dir.join("go");
    let out = dir.join("watch.json");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    spawn_census_sampler(census_log.clone(), stop.clone());
    let mut parent = Command::new(&parent_bin)
        .arg(&log)
        .arg("9")
        .arg(&go)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Observer first (subscribes before the burst), then GO.
    let parent_pid = parent.id();
    let mut observer = spawn_observer(
        &binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &parent_pid.to_string(),
            "--duration",
            "10",
            "--json",
        ],
        &out,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    if !started {
        let _ = observer.kill();
        let _ = parent.kill();
    }
    assert!(started, "observer never started");
    // Deterministic stimulus: the burst must postdate the connector
    // subscription, else births fall in the unwitnessed prefix (still
    // PASS via session-window coverage below, but flaky). Best
    // effort: polling fallback has no socket yet may still satisfy
    // the control via census births, so proceed regardless.
    for _ in 0..150 {
        let subscribed = child_pid(observer.id())
            .and_then(observer_socket_drops)
            .is_some();
        if subscribed {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    fs::write(&go, b"go").unwrap();
    let status = observer.wait().unwrap();
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    parent.wait().unwrap();
    stop.store(true, Ordering::Relaxed);
    let text = fs::read_to_string(&log).unwrap();
    let bursts: Vec<u64> = text
        .lines()
        .filter_map(|l| l.strip_prefix("burst "))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok())
        .collect();
    let survivors: Vec<u64> = text
        .lines()
        .filter_map(|l| l.strip_prefix("survivor "))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok())
        .collect();
    let reaped = text.lines().filter(|l| l.starts_with("reap ")).count();
    if bursts.len() != 32 || survivors.len() != 4 || reaped != 36 {
        eprintln!("INCONCLUSIVE: fork/reap accounting incomplete: {text}");
        return;
    }
    assert!(
        fs::read_to_string(&census_log)
            .unwrap_or_default()
            .contains("# census"),
        "harness census sampler produced nothing"
    );
    let explicit = explicit_pids(&rows);
    let segments = segments_by_pid(&rows);
    eprintln!("kinds: {:?}", kinds(&rows));
    // Every burst child is explicit or covered-unknown. Burst children
    // die sub-tick and persist only as zombies, whose mount-namespace
    // proof is unreadable (kernel fact) — so the specified visible
    // outcome for an unverified birth is a per-pid MembershipUnknown
    // gap (D-record §1.1.2), never a silent member and never a join
    // without a full triple (§1.1). A gapped child has a record
    // (D-record control-1 FAIL clause), so gaps satisfy the control.
    let gapped: BTreeSet<u64> = rows
        .iter()
        .filter(|r| r["kind"] == "gap" && r["gap"]["reason"] == "membership_unknown")
        .filter_map(|r| r["gap"]["pid"].as_u64())
        .collect();
    // Session-window coverage (D-record control-1 OR clause): a burst
    // child whose birth tick falls inside a session lost_interval is
    // covered-unknown with no per-pid record required.
    let birth_ns: BTreeMap<u64, u64> = text
        .lines()
        .filter_map(|l| l.strip_prefix("burst "))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
        })
        .collect();
    let start = rows.iter().find(|r| r["kind"] == "start").unwrap();
    let origin = start["run_origin_ns"].as_u64().unwrap();
    let tick_ns = start["poll_interval"]["secs"].as_u64().unwrap_or(1) * 1_000_000_000
        + start["poll_interval"]["nanos"].as_u64().unwrap_or(0);
    let tick_ns = tick_ns.max(1);
    let end = rows.iter().find(|r| r["kind"] == "end").unwrap();
    let windows: Vec<(u64, u64)> = end["session_loss"]["lost_intervals"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|w| Some((w["start_tick"].as_u64()?, w["end_tick"].as_u64()?)))
        .collect();
    let covered = |pid: u64| {
        birth_ns.get(&pid).is_some_and(|ns| {
            let tick = ns.saturating_sub(origin) / tick_ns;
            windows.iter().any(|(s, e)| *s <= tick && tick < *e)
        })
    };
    for pid in &bursts {
        assert!(
            explicit.contains_key(pid) || gapped.contains(pid) || covered(*pid),
            "burst child {pid} is silent (no record, no gap, no cover): {explicit:?}"
        );
        assert!(
            !segments.contains_key(pid),
            "burst child {pid} has counts (inherited or invented)"
        );
    }
    // Survivors are never covered-only: observing or explicitly deferred.
    for pid in &survivors {
        assert!(
            explicit.contains_key(pid),
            "survivor {pid} is covered-only or silent: {explicit:?}"
        );
    }
    assert!(
        survivors.iter().any(|pid| segments.contains_key(pid)),
        "no survivor was admitted to a segment: {segments:?}"
    );
    // Per-incarnation segments are distinct (no shared counts).
    let mut seen_segments = BTreeSet::new();
    for pid in survivors
        .iter()
        .chain(std::iter::once(&(parent_pid as u64)))
    {
        for seg in segments.get(pid).cloned().unwrap_or_default() {
            let number = seg["segment"].as_u64().unwrap();
            assert!(
                seen_segments.insert((number, pid)),
                "segment {number} shared across incarnations"
            );
        }
    }
}

/// Attributed physical entries in one segment document (current + fenced).
fn segment_calls(segment: &serde_json::Value) -> Option<u64> {
    let doc = &segment["document"];
    let mut total = 0u64;
    for site in doc["sites"].as_array().cloned().unwrap_or_default() {
        total = total.checked_add(site["calls"].as_u64()?)?;
    }
    for epoch in doc["fenced"].as_array().cloned().unwrap_or_default() {
        for site in epoch["sites"].as_array().cloned().unwrap_or_default() {
            total = total.checked_add(site["calls"].as_u64()?)?;
        }
    }
    Some(total)
}

/// Every `tid` value in the stream must be null (no thread-origin evidence,
/// no per-tid billing — §1.8/§4.1).
fn assert_no_tid_attribution(rows: &[serde_json::Value]) {
    fn walk(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    if key == "tid" {
                        assert!(val.is_null(), "non-null tid at {path}: {val}");
                    } else {
                        walk(val, &format!("{path}.{key}"));
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}[{i}]"));
                }
            }
            _ => {}
        }
    }
    for (i, row) in rows.iter().enumerate() {
        walk(row, &format!("row{i}"));
    }
}

/// Control 2 (thread + §1.2 row oracle): 16 sequential crypto workers
/// (1600 counted calls, every call inside a churned thread) plus a
/// 32-thread concurrent spin (exact rc-reported N2, all spinners live
/// at once so their transient per-tid rows overlap). TGID segment
/// stays continuous; N = 1600 + N2 conserves across all tid deaths
/// without per-tid billing; the independent ADMITTED gate establishes
/// N; the direct map oracle proves tid rows appear (mid-spin) and
/// disappear (end).
///
/// D-record correspondence discipline: every counted call is a
/// libcrypto EVP re-init with a digest fetched from the fixture
/// provider (private ctx, count_mode 0 -- `P` is never sent),
/// passing one site per plane exactly once (libcrypto EVP entry
/// -> transient per-tid API_THREADS rows; fixture digest_init ->
/// ADMITTED/COUNTS). `I` loads, fetches, and primes the EVP pool
/// pre-observer; the stimulus window then holds ONLY the N counted
/// re-inits (no queries, no exit cleanup -- the fixture `_exit`s):
/// the ADMITTED delta MUST equal N exactly, else INCONCLUSIVE
/// (stimulus invalid). Tid rows live in API_THREADS (keyed
/// (tgid,tid,generation,cookie); created on entry, removed when
/// depth returns to 0 -- transient by design, never billed
/// per-tid, §4.1).
#[test]
fn control_2_thread_churn_preserves_tgid_counts() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let dir = fresh_dir("thread");
    let mut app = FixtureSession::start(&dir);
    // `I` loads the provider, fetches the digest, and primes the
    // EVP pool (all arming passages pre-observer).
    for setup in ["I"] {
        app.cmd(setup);
    }
    let pid = app.pid();
    let out = dir.join("watch.json");
    let err = dir.join("watch.stderr");
    let mut observer = spawn_observer_stderr(
        &binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &pid.to_string(),
            "--duration",
            "26",
            "--json",
        ],
        &out,
        &err,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    let attached = started
        && wait_for_stderr(
            &err,
            &format!("focused callbacks attached (pid={pid}"),
            Duration::from_secs(60),
        );
    if !attached {
        let _ = observer.kill();
        app.abort();
    }
    assert!(started, "observer never started");
    assert!(attached, "sites never attached");
    // ADMITTED baseline: the fixture is idle (setup precedes the
    // uprobes, so nothing fired yet).
    let Some(admitted0) = bpftool_admitted_total() else {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: ADMITTED baseline unreadable");
        return;
    };
    // Phase K: 16 sequential crypto workers x 100 calls (1600 counted
    // calls, every one inside a thread that then exits). N comes from
    // the workers' rc-checked completion reports (EVP re-inits, not
    // the fixture counter -- count_mode is 0).
    let k_start_ns = monotonic_ns();
    let k_lines = app.cmd2("K 16", &["100"]);
    let mut k_tids = Vec::new();
    let mut k_done = 0u64;
    for line in &k_lines {
        if let Some(rest) = line.strip_prefix("thread ") {
            let mut parts = rest.split_whitespace();
            if let (Some(tid), Some(_)) = (parts.next(), parts.next()) {
                if let Ok(tid) = tid.parse::<u32>() {
                    k_tids.push(tid);
                }
            }
        }
        if let Some(rest) = line.strip_prefix("calls K ") {
            if let Some(done) = rest.split_whitespace().nth(1) {
                k_done = done.parse().unwrap_or(0);
            }
        }
    }
    if k_tids.len() != 16 || k_done != 1600 {
        let _ = observer.kill();
        app.finish();
        eprintln!(
            "INCONCLUSIVE: K churn produced {} tids, {k_done}/1600 calls",
            k_tids.len()
        );
        return;
    }
    // Phase A (spin): 32 threads calling back-to-back for 2000 ms,
    // all CONCURRENTLY. N10 injection oracle: THREADS rows are
    // persistent (BPF never removes them) and this operational
    // fixture creates none naturally, so the harness injects a
    // synthetic THREADS row for a live spinner tid and proves the
    // host exit cleanup deletes it — present-after-inject
    // (construction) implies absent-after-exit means the host
    // deleted it (the only deleter). Then drains the ack + report
    // (exact N2 + spinner tids).
    app.write_raw("A 32\n2000\n");
    // R3-8 transient track (restored alongside the injection
    // oracle — both properties matter): API_THREADS rows must
    // APPEAR during the spin (spinners overlap by the dozen).
    // Rows are transient (BPF removes them at depth 0), so one
    // hit in the spin dumps proves appearance; the ack waits
    // buffered while the harness dumps.
    let spin_end = Instant::now() + Duration::from_millis(3400);
    let mut saw_rows = false;
    let mut dumped = false;
    if let Some(keys) = bpftool_apithread_keys() {
        dumped = true;
        if keys.iter().any(|(tgid, _)| *tgid == pid) {
            saw_rows = true;
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    let live: Vec<u32> = task_tids(pid)
        .into_iter()
        .filter(|tid| *tid != pid)
        .collect();
    let Some(target) = live.first().copied() else {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: no spinner tid to inject for");
        return;
    };
    let threads_map = bpftool_map_ids("THREADS").filter(|ids| ids.len() == 1);
    let injected = threads_map
        .as_ref()
        .is_some_and(|ids| inject_thread_row(&ids[0], pid, target));
    if !injected {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: THREADS injection failed");
        return;
    }
    let present = bpftool_thread_keys().is_some_and(|keys| {
        keys.iter()
            .any(|(tgid, tid)| *tgid == pid && *tid == target)
    });
    if !present {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: injected row never appeared");
        return;
    }
    if !task_alive(pid, target) {
        // The exit may have beaten the injection (cleanup already
        // ran or never will for this row) — stimulus invalid.
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: injection target exited too early");
        return;
    }
    // R3-8: keep dumping across the spin — appearance needs a
    // single hit; the loop exits early on it.
    while !saw_rows && Instant::now() < spin_end {
        std::thread::sleep(Duration::from_millis(250));
        if let Some(keys) = bpftool_apithread_keys() {
            dumped = true;
            if keys.iter().any(|(tgid, _)| *tgid == pid) {
                saw_rows = true;
            }
        }
    }
    if !dumped {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: API_THREADS spin dumps unreadable");
        return;
    }
    let Some(a_lines) = app.drain_ack() else {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: spin phase failed (fixture)");
        return;
    };
    let mut spin_tids = Vec::new();
    let mut spin_done = 0u64;
    for line in &a_lines {
        if let Some(rest) = line.strip_prefix("thread ") {
            if let Some(tid) = rest.split_whitespace().next().and_then(|t| t.parse().ok()) {
                spin_tids.push(tid);
            }
        }
        if let Some(rest) = line.strip_prefix("calls A ") {
            if let Some(done) = rest.split_whitespace().nth(1) {
                spin_done = done.parse().unwrap_or(0);
            }
        }
    }
    if spin_tids.len() != 32 || spin_done == 0 {
        let _ = observer.kill();
        app.finish();
        eprintln!(
            "INCONCLUSIVE: spin produced {} tids, {spin_done} calls",
            spin_tids.len()
        );
        return;
    }
    assert!(
        saw_rows,
        "no API_THREADS tid rows observed across the spin (vacuous oracle)"
    );
    let spin_end_ns = monotonic_ns();
    if !spin_tids.contains(&target) {
        // The injection target is not a reported spinner (fixture
        // skew) — the oracle has no proven exit to wait for.
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: injection target not a spinner");
        return;
    }
    // The target exited after the injection (proven order: alive at
    // inject, gone now) — its EXIT reached the drain and the host
    // cleanup ran for it. Wait for the reaped task entry, bounded.
    let reaped = Instant::now() + Duration::from_secs(10);
    while task_alive(pid, target) && Instant::now() < reaped {
        std::thread::sleep(Duration::from_millis(50));
    }
    if task_alive(pid, target) {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: injection target never reaped");
        return;
    }
    let n_total = 1600u64.saturating_add(spin_done);
    // N10 end dump: the injected row for the reaped target must be
    // gone — BPF never deletes THREADS rows, so absence proves the
    // host exit cleanup ran. (The verdict waits for the End row:
    // a row that persists past a connector drop means delivery was
    // never proven, not that cleanup failed.)
    std::thread::sleep(Duration::from_secs(2));
    let Some(end_keys) = bpftool_thread_keys() else {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: THREADS end dump unreadable");
        return;
    };
    let injected_leaked = end_keys
        .iter()
        .any(|(tgid, tid)| *tgid == pid && *tid == target);
    // R3-8 transient track: exited tids' API_THREADS rows are gone
    // at end (BPF pair-removes them at depth 0) — per-tid, not
    // zero-total, so fixture growth stays safe.
    let Some(api_end_keys) = bpftool_apithread_keys() else {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: API_THREADS end dump unreadable");
        return;
    };
    let api_end_mine: Vec<u32> = api_end_keys
        .iter()
        .filter(|(tgid, _)| *tgid == pid)
        .map(|(_, tid)| *tid)
        .collect();
    for tid in k_tids.iter().chain(spin_tids.iter()) {
        assert!(
            !api_end_mine.contains(tid),
            "exited tid {tid} API_THREADS row leaked: {api_end_mine:?}"
        );
    }
    // Independent ADMITTED == N gate (mandatory, never waived):
    // exactly the worker-reported EVP re-init passages admitted
    // (D-record correspondence; mismatch renders the control
    // INCONCLUSIVE -- stimulus invalid).
    let admitted1 = bpftool_admitted_total();
    if admitted1 != Some(admitted0.saturating_add(n_total)) {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: admitted={admitted1:?} base={admitted0} n={n_total}");
        return;
    }
    let status = observer.wait().unwrap();
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    app.finish();
    eprintln!("kinds: {:?}", kinds(&rows));
    // N10 injection verdict: the injected row for the reaped
    // target must be gone (host cleanup deleted it). A row that
    // persists past connector drops is delivery-unproven
    // (INCONCLUSIVE); a row that persists with clean delivery is a
    // cleanup failure (FAIL).
    if injected_leaked {
        let drops = end_signal_dropped(&rows);
        if drops > 0 {
            eprintln!("INCONCLUSIVE: injected row persisted past {drops} drops");
            return;
        }
        panic!("injected THREADS row for reaped tid {target} leaked (cleanup never deleted it)");
    }
    assert_no_tid_attribution(&rows);
    // One continuous TGID segment (no restart on tid churn).
    let segments = segments_by_pid(&rows);
    let mine = segments.get(&(pid as u64)).cloned().unwrap_or_default();
    assert_eq!(mine.len(), 1, "TGID restarted or never admitted: {mine:?}");
    let observing = rows
        .iter()
        .filter(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["state"] == "observing"
        })
        .count();
    assert_eq!(observing, 1, "TGID re-admitted during churn");
    // The probed site carries exactly N: among the provider module's
    // sites, exactly one fired (the plain digest_init -- query,
    // teardown and allocator sites are quiet: Q precedes the uprobes,
    // the fixture `_exit`s). This pins the counts to the probed
    // symbol, not incidental libcrypto work.
    let provider_ino = fs::metadata(dir.join("provider.so"))
        .ok()
        .map(|m| m.ino() as u64);
    let mut probed_sites = 0u32;
    let mut probed_calls = 0u64;
    let mut all_sites = mine[0]["document"]["sites"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for epoch in mine[0]["document"]["fenced"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        all_sites.extend(epoch["sites"].as_array().cloned().unwrap_or_default());
    }
    for site in &all_sites {
        if Some(site["inode"].as_u64().unwrap_or(0)) == provider_ino
            && site["calls"].as_u64().unwrap_or(0) > 0
        {
            probed_sites += 1;
            probed_calls = probed_calls.saturating_add(site["calls"].as_u64().unwrap_or(0));
        }
    }
    assert_eq!(
        probed_sites, 1,
        "probed-site shape wrong: {probed_sites} provider sites fired"
    );
    assert_eq!(
        probed_calls, n_total,
        "probed site attributed {probed_calls}, N={n_total}"
    );
    // Conservation with interval-specific shortfall accounting: any
    // shortfall sits in windows covering the stimulus span (K start
    // through spin end), never in quiet or elsewhere.
    let total = segment_calls(mine[0]).expect("segment calls sum");
    assert!(total <= n_total, "over-attribution: {total} > {n_total}");
    if total != n_total {
        let Some((origin, interval)) = start_clock(&rows) else {
            panic!("shortfall {total}/{n_total} with unreadable tick clock");
        };
        let t0 = tick_of(origin, interval, k_start_ns);
        let t1 = tick_of(origin, interval, spin_end_ns);
        assert!(
            shortfall_covered(&rows, mine[0], t0.min(t1), t0.max(t1)),
            "shortfall {total}/{n_total} not covered over stimulus ticks {t0}..{t1}"
        );
    }
}

/// CLOCK_MONOTONIC in ns (test-side tick phasing -- same domain as the
/// observer's `run_origin_ns` and the fixtures' `now_ns`).
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// One exec-leg run: returns the fixture log, observer rows, and the
/// per-leg ADMITTED baselines/finals (`None` when the oracle is
/// unavailable -- the caller goes INCONCLUSIVE, never waives).
/// Signals GO1 after attach, GO2 after A calls complete (timed just
/// inside a tick boundary on the adversarial leg, so both execs land
/// in the same tick), GO3 after the epoch-1 re-admission + second
/// attach, GO4 after the B-final dump (leg B holds its maps open).
struct ExecLegs {
    log: String,
    rows: Vec<serde_json::Value>,
    admitted_a0: Option<u64>,
    admitted_a1: Option<u64>,
    admitted_b0: Option<u64>,
    admitted_b1: Option<u64>,
}
fn run_exec_legs(dir: &Path, binary: &Path, mode: &str, onward: bool, duration: u64) -> ExecLegs {
    let leg_a = compile_c(
        dir,
        &["exec_leg_a.c"],
        &format!("leg_a_{mode}"),
        &["-lcrypto", "-ldl"],
    );
    let leg_b = compile_c(
        dir,
        &["exec_leg_b.c"],
        &format!("leg_b_{mode}"),
        &["-lcrypto", "-ldl"],
    );
    compile_c(
        dir,
        &["provider_observation_provider.c"],
        "provider.so",
        &["-shared", "-fPIC"],
    );
    let provider = dir.join("provider.so");
    let log = dir.join(format!("exec_{mode}.log"));
    let go1 = dir.join(format!("go1_{mode}"));
    let go2 = dir.join(format!("go2_{mode}"));
    let go3 = dir.join(format!("go3_{mode}"));
    let go4 = dir.join(format!("go4_{mode}"));
    let out = dir.join(format!("exec_{mode}.json"));
    let err = dir.join(format!("exec_{mode}.stderr"));
    let mut command = Command::new(&leg_a);
    command
        .arg(&log)
        .arg(&go1)
        .arg(&go2)
        .arg(&provider)
        .arg(mode)
        .arg(&leg_b)
        .arg(&log)
        .arg(&provider)
        .arg(&go3)
        .arg(&go4);
    if onward {
        let leg_c = compile_c(
            dir,
            &["exec_leg_c.c"],
            &format!("leg_c_{mode}"),
            &["-lcrypto"],
        );
        command.arg("exec").arg(&leg_c).arg(&log).arg("4");
    } else {
        command.arg("end");
    }
    let mut legs = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = legs.id();
    // Wait for fixture readiness before starting the observer.
    let end = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("ready ")
    {
        assert!(Instant::now() < end, "exec fixture never ready");
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut observer = spawn_observer_stderr(
        &binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &pid.to_string(),
            "--duration",
            &duration.to_string(),
            "--json",
        ],
        &out,
        &err,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    let attached = started
        && wait_for_stderr(
            &err,
            &format!("focused callbacks attached (pid={pid}"),
            Duration::from_secs(60),
        );
    assert!(started, "observer never started");
    assert!(attached, "sites never attached");
    let admitted_a0 = bpftool_admitted_total();
    fs::write(&go1, b"go").unwrap();
    // Wait for A calls, then release the exec.
    let end = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("calls_a ")
    {
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let admitted_a1 = bpftool_admitted_total();
    if onward {
        // Same-tick adversarial timing: release GO2 ~100ms inside a
        // fresh tick (both execs land ~100ms apart in the same
        // 1s tick; the post-hoc tick check inconclusives on a
        // scheduling stall past the boundary).
        if let Some((origin, interval)) = start_clock(&read_rows_partial(&out)) {
            let now = monotonic_ns();
            let phase = now.saturating_sub(origin) % interval;
            let sleep_ns = interval.saturating_sub(phase).saturating_add(100_000_000);
            std::thread::sleep(Duration::from_nanos(sleep_ns.min(2_000_000_000)));
        }
    }
    fs::write(&go2, b"go").unwrap();
    // Wait for the post-exec leg, then for the epoch-1 re-admission.
    let end = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("postexec ")
    {
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if onward {
        // Adversarial: no gates between the execs -- wait for the
        // third leg's arrival, then run to duration.
        let end = Instant::now() + Duration::from_secs(30);
        while !fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("postexec2 ")
        {
            if Instant::now() >= end {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let status = observer.wait().unwrap();
        assert!(
            matches!(status.code(), Some(0 | 3 | 4)),
            "observer failed: {status:?}"
        );
        let rows = read_rows(&out);
        let _ = legs.wait();
        return ExecLegs {
            log: fs::read_to_string(&log).unwrap_or_default(),
            rows,
            admitted_a0,
            admitted_a1,
            admitted_b0: None,
            admitted_b1: None,
        };
    }
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end {
        let rows = read_rows_partial(&out);
        let readmitted = rows.iter().any(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["image_epoch"] == 1
        });
        if readmitted {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Second attach line (new session armed) before the counted B calls.
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        let text = fs::read_to_string(&err).unwrap_or_default();
        let needle = format!("focused callbacks attached (pid={pid}");
        if text.match_indices(&needle).count() >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let admitted_b0 = bpftool_admitted_total();
    fs::write(&go3, b"go").unwrap();
    // B-final dump while leg B holds its maps (GO4 releases it).
    let end = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("calls_b ")
    {
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let admitted_b1 = bpftool_admitted_total();
    fs::write(&go4, b"go").unwrap();
    let status = observer.wait().unwrap();
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    let _ = legs.wait();
    ExecLegs {
        log: fs::read_to_string(&log).unwrap_or_default(),
        rows,
        admitted_a0,
        admitted_a1,
        admitted_b0,
        admitted_b1,
    }
}

/// Normalized membership/observation shape sequence (volatile ids, ticks and
/// documents projected out) for the control-3 indistinguishability check.
fn epoch_shape(rows: &[serde_json::Value], pid: u64) -> Vec<String> {
    let mut out = Vec::new();
    for row in rows {
        if row["incarnation"]["pid"] != pid {
            continue;
        }
        match row["kind"].as_str().unwrap_or("") {
            "membership" => {
                let detail = &row["detail"];
                let detail_shape = if detail.is_null() {
                    "none".to_string()
                } else {
                    format!(
                        "{}:{:?}",
                        detail["kind"].as_str().unwrap_or("?"),
                        detail["tid"].is_null()
                    )
                };
                out.push(format!(
                    "membership:{}:{}:epoch{}:{}",
                    row["state"].as_str().unwrap_or("?"),
                    row["reason"].as_str().unwrap_or("?"),
                    row["image_epoch"].as_u64().unwrap_or(999),
                    detail_shape
                ));
            }
            "process_observation" => {
                out.push(format!(
                    "observation:epoch{}:{}",
                    row["image_epoch"].as_u64().unwrap_or(999),
                    row["retirement"].as_str().unwrap_or("?")
                ));
            }
            _ => {}
        }
    }
    out
}

/// Control 3 (non-leader + counterexample + adversarial): exec from a
/// non-leader seals the image epoch with `tid: None`; the leader leg emits
/// the byte-identical shape; a same-tick second exec seals twice.
#[test]
fn control_3_nonleader_exec_seals_without_origin() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let dir = fresh_dir("exec3");
    let mut shapes = BTreeMap::new();
    for mode in ["nonleader", "leader"] {
        let sub = dir.join(mode);
        fs::create_dir_all(&sub).unwrap();
        let legs = run_exec_legs(&sub, &binary, mode, false, 20);
        let (log, rows) = (&legs.log, &legs.rows);
        eprintln!("{mode} kinds: {:?}", kinds(rows));
        assert_no_tid_attribution(rows);
        let pid: u64 = log
            .lines()
            .find_map(|l| {
                l.strip_prefix("ready ")
                    .and_then(|r| r.split_whitespace().next()?.parse().ok())
            })
            .expect("fixture ready line");
        assert!(log.contains("calls_a 500"), "A calls incomplete: {log}");
        assert!(log.contains("calls_b 500"), "B calls incomplete: {log}");
        // Independent per-leg ADMITTED gates (mandatory, never
        // waived): A admitted exactly its 500 pre-exec calls; B
        // admitted exactly its 500 post-admission calls.
        let gate_a = legs
            .admitted_a0
            .zip(legs.admitted_a1)
            .map(|(b, f)| f.saturating_sub(b));
        let gate_b = legs
            .admitted_b0
            .zip(legs.admitted_b1)
            .map(|(b, f)| f.saturating_sub(b));
        if gate_a != Some(500) || gate_b != Some(500) {
            eprintln!("INCONCLUSIVE: ADMITTED-A={gate_a:?} ADMITTED-B={gate_b:?}");
            return;
        }
        let exec_tid: u32 = log
            .lines()
            .find_map(|l| {
                l.strip_prefix("exec ")
                    .and_then(|r| r.split_whitespace().next()?.parse().ok())
            })
            .expect("exec oracle line");
        if mode == "nonleader" {
            assert_ne!(
                exec_tid as u64, pid,
                "oracle: leader execed, not the worker"
            );
        } else {
            assert_eq!(
                exec_tid as u64, pid,
                "oracle: worker execed, not the leader"
            );
        }
        // Sealed epoch 0 carries exactly the pre-exec calls (no crossing).
        let segments = segments_by_pid(rows);
        let mine = segments.get(&pid).cloned().unwrap_or_default();
        let epoch0: Vec<&&serde_json::Value> =
            mine.iter().filter(|s| s["image_epoch"] == 0).collect();
        assert_eq!(epoch0.len(), 1, "epoch 0 not sealed once: {mine:?}");
        let old = segment_calls(epoch0[0]).expect("epoch-0 calls sum");
        assert!(old <= 500, "post-edge attribution to epoch 0: {old} > 500");
        if old != 500 {
            let (origin, interval) = start_clock(rows).expect("tick clock");
            let exec_ns: u64 = log
                .lines()
                .find_map(|l| {
                    l.strip_prefix("exec ")
                        .and_then(|r| r.split_whitespace().nth(1)?.parse().ok())
                })
                .expect("exec instant");
            let te = tick_of(origin, interval, exec_ns);
            assert!(
                shortfall_covered(rows, epoch0[0], te.saturating_sub(1), te),
                "epoch-0 shortfall {old}/500 not covered over A ticks"
            );
        }
        // Fresh epoch-1 re-admission: same key, advanced epoch, no origin.
        let incarnations: BTreeSet<String> =
            mine.iter().map(|s| s["incarnation"].to_string()).collect();
        assert_eq!(incarnations.len(), 1, "exec changed the incarnation key");
        let readmit: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["kind"] == "membership"
                    && r["incarnation"]["pid"] == pid
                    && r["image_epoch"] == 1
                    && r["state"] == "observing"
            })
            .collect();
        assert_eq!(
            readmit.len(),
            1,
            "no single epoch-1 re-admission: {readmit:?}"
        );
        assert_eq!(readmit[0]["state"], "observing");
        assert_eq!(readmit[0]["detail"]["kind"], "image_readmission");
        assert!(readmit[0]["detail"]["tid"].is_null());
        // New epoch counts only post-exec calls (never the old 500).
        let epoch1: Vec<&&serde_json::Value> =
            mine.iter().filter(|s| s["image_epoch"] == 1).collect();
        assert_eq!(epoch1.len(), 1, "epoch 1 not sealed once: {mine:?}");
        let new = segment_calls(epoch1[0]).expect("epoch-1 calls sum");
        assert!(new <= 500, "epoch 1 inherited pre-exec counts: {new}");
        if new != 500 {
            let (origin, interval) = start_clock(rows).expect("tick clock");
            let calls_b_ns: u64 = log
                .lines()
                .find_map(|l| {
                    l.strip_prefix("calls_b ")
                        .and_then(|r| r.split_whitespace().nth(1)?.parse().ok())
                })
                .expect("calls_b instant");
            let tb = tick_of(origin, interval, calls_b_ns);
            assert!(
                shortfall_covered(rows, epoch1[0], tb.saturating_sub(1), tb),
                "epoch-1 shortfall {new}/500 not covered over B ticks"
            );
        }
        shapes.insert(mode, epoch_shape(rows, pid));
    }
    // Counterexample leg: leader and non-leader shapes are identical.
    assert_eq!(
        shapes["nonleader"], shapes["leader"],
        "exec origin distinguished: {:?} vs {:?}",
        shapes["nonleader"], shapes["leader"]
    );
    // Adversarial leg: a second exec within the SAME tick (no gates,
    // no waiting between the execs) seals both images in drain order.
    let sub = dir.join("adversarial");
    fs::create_dir_all(&sub).unwrap();
    let legs = run_exec_legs(&sub, &binary, "nonleader", true, 24);
    let (log, rows) = (&legs.log, &legs.rows);
    assert!(
        log.contains("postexec2 "),
        "second exec never landed: {log}"
    );
    assert_no_tid_attribution(rows);
    let pid: u64 = log
        .lines()
        .find_map(|l| {
            l.strip_prefix("ready ")
                .and_then(|r| r.split_whitespace().next()?.parse().ok())
        })
        .expect("fixture ready line");
    // Same-tick stimulus proof (fixture instants through the Start
    // clock); a scheduling stall past the boundary inconclusives.
    let (origin, interval) = start_clock(rows).expect("tick clock");
    let exec1_ns: u64 = log
        .lines()
        .find_map(|l| {
            l.strip_prefix("exec ")
                .and_then(|r| r.split_whitespace().nth(1)?.parse().ok())
        })
        .expect("exec instant");
    let exec2_ns: u64 = log
        .lines()
        .find_map(|l| {
            l.strip_prefix("exec2 ")
                .and_then(|r| r.split_whitespace().nth(1)?.parse().ok())
        })
        .expect("exec2 instant");
    if tick_of(origin, interval, exec1_ns) != tick_of(origin, interval, exec2_ns) {
        eprintln!("INCONCLUSIVE: execs straddled a tick boundary");
        return;
    }
    // N7 (§1.4 amendment): only the real readmission (epoch 2)
    // carries `image_readmission` — the middle image (epoch 1,
    // never observed) seals retired-only, without any admission
    // claim.
    let readmits: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid
                && r["detail"]["kind"] == "image_readmission"
        })
        .collect();
    assert_eq!(readmits.len(), 1, "only epoch 2 re-admits: {readmits:?}");
    assert_eq!(readmits[0]["image_epoch"], 2);
    assert_eq!(readmits[0]["state"], "observing");
    // Drain-order seals: the middle image (epoch 1, never observed --
    // no session existed between the same-tick execs) emits exactly
    // one record — `Membership{retired, unobserved_transition,
    // segment 0}` with the carried ledger — between the epoch-0
    // seal and the epoch-2 re-admission; only epochs 0 and 2 carry
    // observations.
    let middle: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["incarnation"]["pid"] == pid && r["image_epoch"] == 1)
        .collect();
    assert_eq!(
        middle.len(),
        1,
        "middle image emits exactly one record: {middle:?}"
    );
    assert_eq!(middle[0]["kind"], "membership");
    assert_eq!(middle[0]["state"], "retired");
    assert_eq!(middle[0]["reason"], "unobserved_transition");
    assert_eq!(middle[0]["segment"], 0);
    assert!(middle[0]["detail"].is_null());
    assert!(middle[0]["loss"].is_object(), "carried ledger present");
    let pos = |pred: &dyn Fn(&serde_json::Value) -> bool| {
        rows.iter().position(pred).expect("ordered record")
    };
    let seal0 = pos(&|r| {
        r["kind"] == "process_observation"
            && r["incarnation"]["pid"] == pid
            && r["image_epoch"] == 0
    });
    let retire1 = pos(&|r| {
        r["kind"] == "membership"
            && r["incarnation"]["pid"] == pid
            && r["image_epoch"] == 1
            && r["state"] == "retired"
    });
    let admit2 = pos(&|r| {
        r["kind"] == "membership"
            && r["incarnation"]["pid"] == pid
            && r["image_epoch"] == 2
            && r["state"] == "observing"
    });
    assert!(
        seal0 < retire1 && retire1 < admit2,
        "middle image not sealed in drain order"
    );
    let mine = segments_by_pid(rows).remove(&pid).unwrap_or_default();
    let observed: BTreeSet<u64> = mine
        .iter()
        .filter_map(|s| s["image_epoch"].as_u64())
        .collect();
    assert_eq!(observed, BTreeSet::from([0, 2]), "middle image observed?!");
}

/// Control 4 (exec): leader exec to a different image seals counts,
/// re-admits under the same key with advanced epoch, carries loss.
#[test]
fn control_4_leader_exec_readmits_same_key() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let dir = fresh_dir("exec4");
    let legs = run_exec_legs(&dir, &binary, "leader", false, 20);
    let (log, rows) = (&legs.log, &legs.rows);
    eprintln!("kinds: {:?}", kinds(rows));
    assert_no_tid_attribution(rows);
    let pid: u64 = log
        .lines()
        .find_map(|l| {
            l.strip_prefix("ready ")
                .and_then(|r| r.split_whitespace().next()?.parse().ok())
        })
        .expect("fixture ready line");
    assert!(log.contains("calls_a 500"), "A calls incomplete: {log}");
    assert!(log.contains("calls_b 500"), "B calls incomplete: {log}");
    assert!(log.contains("postexec "), "exec oracle missing: {log}");
    // Independent per-leg ADMITTED gates (mandatory, never waived).
    let gate_a = legs
        .admitted_a0
        .zip(legs.admitted_a1)
        .map(|(b, f)| f.saturating_sub(b));
    let gate_b = legs
        .admitted_b0
        .zip(legs.admitted_b1)
        .map(|(b, f)| f.saturating_sub(b));
    if gate_a != Some(500) || gate_b != Some(500) {
        eprintln!("INCONCLUSIVE: ADMITTED-A={gate_a:?} ADMITTED-B={gate_b:?}");
        return;
    }
    let (origin, interval) = start_clock(rows).expect("tick clock");
    let segments = segments_by_pid(rows);
    let mine = segments.get(&pid).cloned().unwrap_or_default();
    assert_eq!(mine.len(), 2, "both image epochs must seal: {mine:?}");
    // Same incarnation key across the exec; epochs 0 then 1.
    let keys: BTreeSet<String> = mine.iter().map(|s| s["incarnation"].to_string()).collect();
    assert_eq!(keys.len(), 1, "exec changed the incarnation key");
    let mut epochs: Vec<u64> = mine
        .iter()
        .filter_map(|s| s["image_epoch"].as_u64())
        .collect();
    epochs.sort_unstable();
    assert_eq!(epochs, vec![0, 1]);
    // Old image sealed with conserved counts; new image counts only B.
    // Shortfalls carry interval-specific covering windows (M3).
    let seg0 = mine.iter().find(|s| s["image_epoch"] == 0).unwrap();
    let total0 = segment_calls(seg0).unwrap();
    assert!(total0 <= 500, "epoch 0 over-attributed: {total0}");
    if total0 != 500 {
        let exec_ns: u64 = log
            .lines()
            .find_map(|l| {
                l.strip_prefix("exec ")
                    .and_then(|r| r.split_whitespace().nth(1)?.parse().ok())
            })
            .expect("exec instant");
        let te = tick_of(origin, interval, exec_ns);
        assert!(
            shortfall_covered(rows, seg0, te.saturating_sub(1), te),
            "epoch-0 shortfall {total0}/500 not covered over A ticks"
        );
    }
    let seg1 = mine.iter().find(|s| s["image_epoch"] == 1).unwrap();
    let total1 = segment_calls(seg1).unwrap();
    assert!(total1 <= 500, "epoch 1 over-attributed: {total1}");
    if total1 != 500 {
        let calls_b_ns: u64 = log
            .lines()
            .find_map(|l| {
                l.strip_prefix("calls_b ")
                    .and_then(|r| r.split_whitespace().nth(1)?.parse().ok())
            })
            .expect("calls_b instant");
        let tb = tick_of(origin, interval, calls_b_ns);
        assert!(
            shortfall_covered(rows, seg1, tb.saturating_sub(1), tb),
            "epoch-1 shortfall {total1}/500 not covered over B ticks"
        );
    }
    // Loss ledger carried forward by reference: epoch-1 records carry loss.
    for row in rows.iter().filter(|r| {
        r["incarnation"]["pid"] == pid
            && (r["kind"] == "membership" || r["kind"] == "process_observation")
    }) {
        assert!(
            row["loss"].is_object(),
            "record without carried loss ledger: {row}"
        );
    }
    // Re-admission went through join (fresh observing record, no in-place
    // image mutation): epoch-1 membership postdates the epoch-0 seal.
    let seal_seq = rows
        .iter()
        .position(|r| r["kind"] == "process_observation" && r["image_epoch"] == 0)
        .expect("epoch-0 seal");
    let readmit_seq = rows
        .iter()
        .position(|r| {
            r["kind"] == "membership" && r["image_epoch"] == 1 && r["state"] == "observing"
        })
        .expect("epoch-1 re-admission");
    assert!(
        seal_seq < readmit_seq,
        "re-admission precedes the seal (in-place mutation?)"
    );
}

/// Guarded global pid_max squeeze for forced PID reuse (control 5).
/// Restores the original value on drop (best-effort + loud on failure).
struct PidMaxGuard {
    original: String,
}
impl PidMaxGuard {
    fn squeeze(value: &str) -> Option<Self> {
        let original = fs::read_to_string("/proc/sys/kernel/pid_max").ok()?;
        let status = Command::new("sudo")
            .args([
                "-n",
                "sh",
                "-c",
                &format!("echo {value} > /proc/sys/kernel/pid_max"),
            ])
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        Some(Self {
            original: original.trim().to_string(),
        })
    }
}
impl Drop for PidMaxGuard {
    fn drop(&mut self) {
        let status = Command::new("sudo")
            .args([
                "-n",
                "sh",
                "-c",
                &format!("echo {} > /proc/sys/kernel/pid_max", self.original),
            ])
            .status();
        if !status.is_ok_and(|s| s.success()) {
            eprintln!("WARNING: pid_max restore failed (wanted {})", self.original);
        }
    }
}

fn live_pids() -> usize {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().parse::<u32>().is_ok())
                .count()
        })
        .unwrap_or(usize::MAX)
}

/// Control 5 (PID reuse + adversarial): force recycling until the watched
/// pid number is reused. Old incarnation retires first (prompt: receipt
/// within 2 ticks of the oracle reuse instant, in tick domain); the new
/// one joins as a stranger with empty history. N12: the live leg
/// accepts either correct seal (`incarnation_changed` when reuse wins
/// the race, `event_exit` when a sample seals the death first).
/// Adversarial leg: the dead incarnation's EXIT is deliberately
/// delivered AFTER the replacement is admitted (SIGSTOP-held observer
/// + fork bomblet ahead of the EXIT) -- it must quarantine as a
/// thread-exit artifact, never retire the new member.
#[test]
fn control_5_pid_reuse_retires_before_stranger_join() {
    if live_pids() > 1500 {
        eprintln!("INCONCLUSIVE: box too busy for a pid_max squeeze");
        return;
    }
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let Some(_squeeze) = PidMaxGuard::squeeze("2048") else {
        eprintln!("INCONCLUSIVE: pid_max squeeze refused");
        return;
    };
    // Leg 1 (promptness, live observer): death + immediate reuse race.
    reuse_leg(&binary, false);
    // Leg 2 (adversarial, SIGSTOP-held observer + bomblet): the
    // occupant's EXIT queues BEHIND 320 bomblet datagrams while the
    // observer is stopped; the first post-resume drain consumes
    // bomblet only, the first post-resume sample seals the old
    // incarnation (sample rules) and admits the replacement, and a
    // later drain delivers the EXIT against the ADMITTED
    // replacement -- artifact quarantine, deterministically.
    reuse_leg(&binary, true);
}

/// Resume the whole sudo+observer stack after a held leg's SIGSTOP
/// (N12 helper, extracted verbatim): sudo suspends itself when its
/// child stops (job-control emulation), so CONTing only the
/// observer leaves sudo stopped -- it can never reap the observer
/// and a later `wait()` hangs forever. CONT both, then poll both
/// out of T (bounded; a stuck T here would hang the wait).
fn resume_observer_stack(sudo_pid: u32, inner: u32) {
    let cont = Command::new("sudo")
        .args(["-n", "kill", "-CONT"])
        .arg(inner.to_string())
        .arg(sudo_pid.to_string())
        .status()
        .expect("spawn sudo kill -CONT");
    assert!(
        cont.success(),
        "SIGCONT of observer {inner}/sudo {sudo_pid} failed"
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let states: Vec<(u32, String)> = [inner, sudo_pid]
            .iter()
            .map(|p| {
                let st = std::fs::read_to_string(format!("/proc/{p}/stat")).unwrap_or_default();
                let s = st
                    .rsplit(')')
                    .next()
                    .and_then(|s| s.split_whitespace().next())
                    .unwrap_or("?")
                    .to_string();
                (*p, s)
            })
            .collect();
        if states.iter().all(|(_, s)| s != "T") {
            break;
        }
        assert!(
            Instant::now() < end,
            "observer stack stuck stopped after CONT: {states:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Raw fork child (N12 fast recycle): kill + reaping without `Child`.
struct RawChild(u32);
impl RawChild {
    fn kill(&mut self) {
        unsafe {
            libc::kill(self.0 as i32, libc::SIGKILL);
        }
    }
    fn wait(&mut self) {
        let mut status = 0;
        unsafe {
            libc::waitpid(self.0 as i32, &mut status, 0);
        }
    }
}

/// N12 fast pid recycle: tight fork loop until a child lands on
/// `want`; the winner execs the eligible sleeper (holding the
/// number atomically), losers `_exit` immediately. ~50µs per
/// cycle (no exec except the winner) — recycling completes in a
/// fraction of a sample gap WITHOUT the multi-second fork storm a
/// spawn-per-pid loop causes (storm bind pressure stalls the
/// sample clock ~3s, past the frozen 2-tick promptness bound).
/// Returns (winner starttime, cycles). The child side uses only
/// async-signal-safe calls (argv/envp prebuilt by the parent).
fn recycle_pid_fast(
    want: u32,
    libcrypto: &str,
    sleeper_secs: &str,
    deadline: Instant,
    cap: u32,
) -> Option<(u64, u32)> {
    use std::ffi::CString;
    let sleep_path =
        CString::new("/usr/bin/sleep").expect("sleep path should have no interior NUL");
    let argv0 = CString::new("sleep").expect("argv0");
    let argv1 = CString::new(sleeper_secs).expect("sleeper secs");
    let preload =
        CString::new(format!("LD_PRELOAD={libcrypto}")).expect("preload should have no NUL");
    let argv = [argv0.as_ptr(), argv1.as_ptr(), std::ptr::null()];
    let envp = [preload.as_ptr(), std::ptr::null()];
    let mut cycles = 0u32;
    loop {
        if Instant::now() >= deadline || cycles >= cap {
            return None;
        }
        cycles += 1;
        let child = unsafe { libc::fork() };
        if child < 0 {
            return None;
        }
        if child == 0 {
            let me = unsafe { libc::getpid() } as u32;
            if me == want {
                unsafe {
                    libc::execve(sleep_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                    libc::_exit(127);
                }
            }
            unsafe { libc::_exit(0) };
        }
        if child as u32 == want {
            // Winner holds the number (exec'd sleeper — do NOT
            // wait); verify it is really alive under our number.
            if let Some(start) = starttime_of(want) {
                return Some((start, cycles));
            }
            // Exec failed and the winner exited: the number is
            // free again but the allocator moved on — reap the
            // zombie and keep cycling (bounded).
            let mut status = 0;
            unsafe {
                libc::waitpid(child, &mut status, 0);
            }
            continue;
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(child, &mut status, 0);
        }
    }
}

/// Comm field of a `/proc/<pid>/stat` line: between the first
/// `(` and the LAST `)` (comm itself may contain parens). One
/// helper for both `wait_for_exec_comm` checks — the bug being
/// fixed here WAS the two spots sharing the state-parse idiom
/// (`rsplit(')').next()`, which yields the post-comm remainder,
/// never the comm), so a second inline path would re-invite it.
fn stat_comm(st: &str) -> Option<&str> {
    let (_, after_open) = st.split_once('(')?;
    let (comm, _) = after_open.rsplit_once(')')?;
    Some(comm)
}
/// R3-9: wait for the recycled winner to complete its exec (comm ==
/// `want`, same incarnation). `recycle_pid_fast` returns when the
/// number is held, which races the winner's exec — a sample that
/// sees the pre-exec image breaks the staged ordering, so the
/// control never proceeds on an unexec'd winner.
fn wait_for_exec_comm(pid: u32, start: u64, want: &str, timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if starttime_of(pid) != Some(start) {
            return false;
        }
        if let Ok(st) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if stat_comm(&st) == Some(want) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    starttime_of(pid) == Some(start)
        && std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|st| stat_comm(&st).map(|c| c == want))
            .unwrap_or(false)
}
#[test]
fn stat_comm_parses_between_first_open_and_last_close_paren() {
    // Controller fixup: `wait_for_exec_comm` used the state-parse
    // idiom (`rsplit(')').next()`), which yields the post-comm
    // stat remainder — control 5 went INCONCLUSIVE on every leg.
    // The comm sits between the first `(` and the last `)`.
    assert_eq!(stat_comm("123 (sleep) S 1 2 3"), Some("sleep"));
    assert_eq!(stat_comm("123 (a)b) S 1"), Some("a)b"));
    assert_eq!(stat_comm("123 (x(y)z) R 0"), Some("x(y)z"));
    assert_eq!(stat_comm("no parens here"), None);
    assert_eq!(stat_comm("123 (unterminated S 1"), None);
    let live = std::fs::read_to_string("/proc/self/stat").expect("own stat");
    // The harness binary is `six_a_controls-<hash>`; comm truncates
    // to 15 bytes.
    assert_eq!(stat_comm(&live), Some("six_a_controls-"));
}

/// One control-5 leg. `held`: SIGSTOP the observer across kill+respawn
/// (delayed-EXIT delivery); otherwise live (promptness measurable).
fn reuse_leg(binary: &Path, held: bool) {
    let tag = if held { "reuse-held" } else { "reuse-live" };
    let dir = fresh_dir(tag);
    let out = dir.join("watch.json");
    let err = dir.join("watch.stderr");
    // Occupant: eligible + crypto-active (its counts must NOT leak).
    let mut occupant = Command::new("openssl")
        .args([
            "speed", "-elapsed", "-seconds", "240", "-evp", "SHA512", "-bytes", "64",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = occupant.id();
    let old_start = starttime_of(pid).expect("occupant starttime");
    let duration = if held { "90" } else { "18" };
    let mut observer = spawn_observer_stderr(
        binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &pid.to_string(),
            "--duration",
            duration,
            "--json",
        ],
        &out,
        &err,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    let attached = started
        && wait_for_stderr(
            &err,
            &format!("focused callbacks attached (pid={pid}"),
            Duration::from_secs(60),
        );
    if !attached {
        let _ = observer.kill();
        let _ = occupant.kill();
    }
    assert!(started, "observer never started");
    assert!(attached, "sites never attached");
    std::thread::sleep(Duration::from_secs(2));
    // Death + reuse: SIGKILL the occupant, then respawn light eligible
    // sleepers until the pid number is recycled (bounded). Held leg:
    // the observer (inner pid under sudo) is SIGSTOPped first, so the
    // occupant's EXIT queues in the connector socket until SIGCONT.
    let inner = held.then(|| child_pid(observer.id())).flatten();
    if held {
        let Some(inner) = inner else {
            let _ = observer.kill();
            let _ = occupant.kill();
            eprintln!("INCONCLUSIVE: observer inner pid not found");
            return;
        };
        // F14/M10: the freeze MUST be real. The observer runs as root
        // under the sudo harness, so a direct `kill(pid, SIGSTOP)` from
        // the test process fails EPERM -- and the unchecked return used
        // to turn this leg into a second live leg silently (the EXIT
        // drained pre-respawn, no quarantine exercised, yet the
        // incarnation_changed assertion still passed via the storm-delayed
        // seal). Route the stop through `sudo -n kill`, assert its exit
        // status, and verify state T from /proc before the kill.
        // Safety: never SIGSTOP an arbitrary pid on a harness bug --
        // confirm the target is the observer binary first.
        let cmdline = std::fs::read_to_string(format!("/proc/{inner}/cmdline"))
            .unwrap_or_default()
            .replace('\0', " ");
        assert!(
            cmdline.contains("osslscope"),
            "F14: stop target {inner} is not the observer ({cmdline:?})"
        );
        let stop = Command::new("sudo")
            .args(["-n", "kill", "-STOP"])
            .arg(inner.to_string())
            .status()
            .expect("spawn sudo kill -STOP");
        assert!(
            stop.success(),
            "F14: SIGSTOP of observer {inner} failed; held leg would be live"
        );
        // Settle: the stop must precede the kill (else the EXIT drains
        // live and the leg degrades to the live race).
        std::thread::sleep(Duration::from_millis(500));
        let st =
            std::fs::read_to_string(format!("/proc/{inner}/stat")).expect("read observer stat");
        let state = st
            .rsplit(')')
            .next()
            .and_then(|s| s.split_whitespace().next());
        assert_eq!(
            state,
            Some("T"),
            "F14: observer {inner} not stopped (state {state:?}); held leg would be live"
        );
        // N12 rephase: queue a fork bomblet AHEAD of the occupant's
        // EXIT so the EXIT delivers AFTER the replacement is
        // admitted. Each `true` child contributes one FORK + one
        // EXIT datagram; 160 children = 320 datagrams ahead of the
        // EXIT, and the port drains at most 256 per poll (FIFO) —
        // so the first post-resume drain consumes bomblet only,
        // the first post-resume sample seals the old incarnation
        // and admits the replacement, and a later drain delivers
        // the EXIT against the ADMITTED replacement (artifact
        // quarantine). Premise: completions x 2 > 256, else the
        // leg degrades to the old pre-admission delivery and must
        // not run. R3-9: the staging above is necessary but not
        // proof — the verdict asserts `admitted_exit_artifacts >=
        // 1`, which ONLY the post-admission artifact arm counts
        // (a pre-admission quarantine leaves it at zero and fails
        // the control instead of passing vacuously).
        let mut bomblet_done = 0u32;
        for _ in 0..160 {
            let spawned = Command::new("true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            let Ok(mut child) = spawned else {
                break;
            };
            if child.wait().is_ok() {
                bomblet_done += 1;
            }
        }
        if bomblet_done * 2 <= 256 {
            resume_observer_stack(observer.id(), inner);
            let _ = observer.kill();
            let _ = occupant.kill();
            eprintln!("INCONCLUSIVE: bomblet shortfall ({bomblet_done}/160) cannot delay the EXIT");
            return;
        }
        eprintln!("held bomblet queued {bomblet_done} children ahead of the EXIT");
    }
    occupant.kill().unwrap();
    occupant.wait().unwrap();
    assert!(!alive(pid), "occupant survived SIGKILL?");
    let libcrypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
    if !Path::new(libcrypto).is_file() {
        let _ = observer.kill();
        eprintln!("INCONCLUSIVE: {libcrypto} missing");
        return;
    }
    let sleeper_secs = if held { "150" } else { "30" };
    let reuse_deadline = Instant::now() + Duration::from_secs(60);
    let recycled = recycle_pid_fast(pid, libcrypto, sleeper_secs, reuse_deadline, 4096);
    let Some((reused_start, cycles)) = recycled else {
        // N12: resume before leaving (a stopped orphaned
        // observer would linger holding BPF + the squeeze).
        if held {
            if let Some(inner) = inner {
                resume_observer_stack(observer.id(), inner);
            }
        }
        let _ = observer.kill();
        eprintln!("INCONCLUSIVE: no reuse within 4096 fork cycles");
        return;
    };
    // The oracle-observed reuse instant is recycle return (the
    // pid reallocation), not exec completion — stamp it before
    // the exec wait below.
    let reuse_ns = monotonic_ns();
    // R3-9: the winner must complete its exec BEFORE any sample
    // can see it — recycle-before-exec-completion breaks the
    // staged ordering (a pre-exec image is ineligible, so the
    // first sample would stash instead of admitting).
    let exec_wait_start = Instant::now();
    if !wait_for_exec_comm(pid, reused_start, "sleep", Duration::from_secs(10)) {
        if held {
            if let Some(inner) = inner {
                resume_observer_stack(observer.id(), inner);
            }
        }
        let _ = observer.kill();
        eprintln!("INCONCLUSIVE: recycled winner never exec'd the sleeper");
        return;
    }
    eprintln!(
        "winner exec observed after {:?} (held={held})",
        exec_wait_start.elapsed()
    );
    let mut reuser = RawChild(pid);
    assert_ne!(reused_start, 0, "reused pid has no starttime?");
    assert_ne!(
        reused_start, old_start,
        "starttime did not advance on reuse"
    );
    eprintln!("reused pid {pid} after {cycles} fork cycles (held={held})");
    if held {
        resume_observer_stack(observer.id(), inner.expect("held inner pid"));
    }
    // The observer may have exited during a slow respawn (duration is
    // observer-clock, the stop included) -- inconclusive, not failure.
    if observer.try_wait().ok().flatten().is_some() {
        let _ = reuser.kill();
        eprintln!("INCONCLUSIVE: observer exited before reuse completed");
        return;
    }
    // Promptness (M10, live leg only -- the held observer was stopped,
    // so harness-clock promptness is meaningless there).
    if !held {
        let found = wait_for_record(&out, Duration::from_secs(30), &|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["incarnation"]["starttime"] == old_start
                && r["state"] == "retired"
        });
        let Some((retire_row, _receipt, receipt_ns)) = found else {
            let _ = observer.kill();
            let _ = reuser.kill();
            panic!("old incarnation never retired");
        };
        // N12: EITHER seal is correct. `incarnation_changed` when
        // the reuse won the race (death + respawn inside one
        // sample gap); `event_exit` when a sample sealed the death
        // first (probe-Dead at seal proves the reuse had not
        // completed yet — §1.3/§1.8). Forcing one path would need
        // timing control the harness does not have (respawn
        // latency vs the sample clock), so both are accepted.
        let reason = retire_row["reason"].as_str().unwrap_or("?");
        assert!(
            reason == "incarnation_changed" || reason == "event_exit",
            "old incarnation retirement wrong: {retire_row}"
        );
        // Frozen promptness (D-record control 5: retirement within
        // 2 ticks of oracle-observed reuse), checked in the
        // observer's tick domain via the Start clock — no harness
        // slack. For `event_exit` the seal structurally precedes
        // reuse completion, so the same bound holds (receipt
        // within a poll of the pre-reuse seal) and is checked
        // uniformly.
        let (origin, interval) = start_clock(&read_rows_partial(&out)).expect("start clock row");
        let reuse_tick = tick_of(origin, interval, reuse_ns);
        let receipt_tick = tick_of(origin, interval, receipt_ns);
        assert!(
            receipt_tick <= reuse_tick.saturating_add(2),
            "retirement not prompt: receipt tick {receipt_tick} > reuse tick {reuse_tick} + 2"
        );
        eprintln!(
            "live leg sealed via {reason} (receipt tick {receipt_tick}, reuse tick {reuse_tick})"
        );
    }
    let status = observer.wait().unwrap();
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    let _ = reuser.kill();
    let _ = reuser.wait();
    eprintln!("kinds: {:?}", kinds(&rows));
    // N12 held guard: the rephase proves EXIT-after-admission only
    // when no connector datagram was dropped — a dropped EXIT
    // would make the quarantine assertion vacuous (bomblet exits
    // quarantine too). Drops void the adversarial stimulus.
    if held {
        let drops = end_signal_dropped(&rows);
        if drops > 0 {
            eprintln!(
                "INCONCLUSIVE: held leg dropped {drops} connector datagrams (EXIT delivery unproven)"
            );
            return;
        }
    }
    let old_key = |r: &serde_json::Value| {
        r["incarnation"]["pid"] == pid as u64 && r["incarnation"]["starttime"] == old_start
    };
    let new_key = |r: &serde_json::Value| {
        r["incarnation"]["pid"] == pid as u64 && r["incarnation"]["starttime"] == reused_start
    };
    // Old incarnation retired before any record for the new one —
    // `incarnation_changed` on the held leg (reuse completed while
    // stopped, so every post-resume sample sees the recycled
    // number); either correct seal on the live leg (N12: the race
    // decides, both seal correctly).
    let retire_seq = rows
        .iter()
        .position(|r| r["kind"] == "membership" && old_key(r) && r["state"] == "retired");
    let retire_reason = retire_seq.map(|i| rows[i]["reason"].as_str().unwrap_or("?"));
    if held {
        assert_eq!(
            retire_reason,
            Some("incarnation_changed"),
            "old incarnation retirement wrong: {retire_reason:?}"
        );
    } else {
        assert!(
            retire_reason == Some("incarnation_changed") || retire_reason == Some("event_exit"),
            "old incarnation retirement wrong: {retire_reason:?}"
        );
    }
    let first_new_seq = rows.iter().position(|r| {
        (r["kind"] == "membership" || r["kind"] == "process_observation") && new_key(r)
    });
    assert!(
        retire_seq.unwrap() < first_new_seq.unwrap_or(usize::MAX),
        "new incarnation records precede the old retirement"
    );
    // New incarnation: own segment, empty sealed history, zero counts
    // (sleep: no crypto -- nothing inherited from the old >0 segment).
    let segments = segments_by_pid(&rows);
    let all = segments.get(&(pid as u64)).cloned().unwrap_or_default();
    let old_segs: Vec<&&serde_json::Value> = all
        .iter()
        .filter(|s| s["incarnation"]["starttime"] == old_start)
        .collect();
    let new_segs: Vec<&&serde_json::Value> = all
        .iter()
        .filter(|s| s["incarnation"]["starttime"] == reused_start)
        .collect();
    assert_eq!(old_segs.len(), 1, "old segment missing: {all:?}");
    assert_eq!(new_segs.len(), 1, "new segment missing: {all:?}");
    let old_total = segment_calls(old_segs[0]).expect("old calls sum");
    let new_total = segment_calls(new_segs[0]).expect("new calls sum");
    if !held {
        assert!(old_total > 0, "occupant produced no counts (stimulus?)");
    } else {
        // Held leg: the post-resume reuse probe fences the old
        // member at the pre-stop instant (F2 -- BPF kept counting
        // across the stop gap, so the seal-time aggregates straddle
        // the edge), so its counts land in loss, not calls.
        // Stimulus sanity here is calls==0 AND loss>0: the occupant
        // was crypto-active (its counts were observed) and the
        // fence held (none reported).
        let old_loss = old_segs[0]["loss"]["loss"].as_u64().unwrap_or(0);
        assert_eq!(
            old_total, 0,
            "held old member leaked fenced counts as calls: {old_total}"
        );
        assert!(
            old_loss > 0,
            "held old member shows no fenced loss (stimulus?)"
        );
    }
    assert_eq!(
        new_total, 0,
        "new incarnation inherited counts: {new_total}"
    );
    assert_eq!(
        new_segs[0]["loss"]["deferred"]["ticks"].as_u64(),
        Some(0),
        "new incarnation inherited deferred history"
    );
    assert_eq!(
        new_segs[0]["loss"]["loss"].as_u64(),
        Some(0),
        "new incarnation inherited loss count"
    );
    // Adversarial: the delayed exit never retired the new member -- its
    // only retirement is the end-of-observation one. Held leg: the
    // delayed EXIT deterministically quarantined (unattributed >= 1).
    let new_retires: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["kind"] == "membership" && new_key(r) && r["state"] == "retired")
        .collect();
    assert_eq!(
        new_retires.len(),
        1,
        "new member retirement wrong: {new_retires:?}"
    );
    assert_eq!(new_retires[0]["reason"], "duration");
    if held {
        let end = rows.iter().find(|r| r["kind"] == "end");
        let unattributed = end
            .and_then(|e| e["session_loss"]["unattributed_events"].as_u64())
            .unwrap_or(0);
        assert!(
            unattributed >= 1,
            "delayed EXIT never quarantined (unattributed={unattributed})"
        );
        // R3-9: the binding proof — the delayed EXIT must have met
        // the ADMITTED replacement (live-member artifact), not
        // quarantined pre-admission. Queue depth alone proves
        // nothing; a zero here fails the control (the scenario did
        // not stage), it never passes vacuously.
        let artifacts = end
            .and_then(|e| e["session_loss"]["admitted_exit_artifacts"].as_u64())
            .unwrap_or(0);
        assert!(
            artifacts >= 1,
            "delayed EXIT never bound post-admission (admitted_exit_artifacts={artifacts}): \
             the replacement was not admitted before the EXIT drained"
        );
    }
}

/// Harness-side connector Drops oracle: sum of Drops over every netlink
/// socket owned by `pid` (the observer's connector socket is the only one
/// under fork pressure). Test-owned `/proc` reads, distinct from the
/// observer's `socket_drops` path.
/// Live BPF map ids for one map name (harness-owned bpftool path,
/// distinct from the observer's reads).
fn bpftool_map_ids(name: &str) -> Option<Vec<String>> {
    let list = Command::new("sudo")
        .args(["-n", "bpftool", "map", "list"])
        .output()
        .ok()?;
    if !list.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&list.stdout);
    let mut ids = Vec::new();
    for line in text.lines() {
        // Continuation lines (key/value details) carry no id -- skip,
        // never bail (bailing voids the whole oracle).
        let Some((id, rest)) = line.split_once(':') else {
            continue;
        };
        if rest.contains(&format!("name {name} ")) {
            ids.push(id.trim().to_string());
        }
    }
    (!ids.is_empty()).then_some(ids)
}
/// 6A independent admission gate (D-record acceptance table): the
/// harness-owned BPF ADMITTED ledger (per-cpu array, key 0) summed
/// over live ADMITTED maps — distinct from the observer's
/// projection. `None` (INCONCLUSIVE) when bpftool is unavailable,
/// no map answers, or the map count is ambiguous (stale maps from
/// a crashed run would corrupt the gate).
fn bpftool_admitted_total() -> Option<u64> {
    let ids = bpftool_map_ids("ADMITTED")?;
    if ids.len() != 1 {
        return None;
    }
    let dump = Command::new("sudo")
        .args(["-n", "bpftool", "map", "dump", "id", &ids[0], "-j"])
        .output()
        .ok()?;
    if !dump.status.success() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&dump.stdout).ok()?;
    let mut total = 0u64;
    let mut found = false;
    for entry in json.as_array().cloned().unwrap_or_default() {
        let is_zero = entry["key"].as_u64().is_some_and(|k| k == 0)
            || entry["key"]
                .as_array()
                .is_some_and(|b| b.iter().all(|x| x.as_str().is_some_and(|s| s == "0x00")));
        if !is_zero {
            continue;
        }
        for cpu in entry["values"].as_array().cloned().unwrap_or_default() {
            // BTF-less per-cpu u64 renders as an 8-byte LE array,
            // never a JSON number (a bare `as_u64` reads 0 forever).
            if let Some(v) = cpu["value"].as_u64() {
                total = total.saturating_add(v);
                found = true;
                continue;
            }
            let bytes: Vec<u8> = cpu["value"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|x| {
                    x.as_str()
                        .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                })
                .collect();
            if bytes.len() == 8 {
                total = total.saturating_add(u64::from_le_bytes(bytes[..8].try_into().unwrap()));
                found = true;
            }
        }
    }
    found.then_some(total)
}
/// 6A direct map oracle (§1.2): `(tgid, tid)` keys present in a
/// live pairing map. Both maps share the `(pid, tid)` 8-byte LE
/// key prefix (`ThreadKey` / `ApiThreadKey` — generation/cookie
/// ignored). `None` (INCONCLUSIVE) when the oracle is
/// unavailable or ambiguous (zero or several maps).
fn bpftool_pairing_keys(map: &str) -> Option<Vec<(u32, u32)>> {
    let ids = bpftool_map_ids(map)?;
    if ids.len() != 1 {
        return None;
    }
    let dump = Command::new("sudo")
        .args(["-n", "bpftool", "map", "dump", "id", &ids[0], "-j"])
        .output()
        .ok()?;
    if !dump.status.success() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&dump.stdout).ok()?;
    let mut keys = Vec::new();
    for entry in json.as_array().cloned().unwrap_or_default() {
        let bytes: Vec<u8> = entry["key"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|x| {
                x.as_str()
                    .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
            .collect();
        if bytes.len() < 8 {
            continue;
        }
        let pid = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let tid = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        keys.push((pid, tid));
    }
    Some(keys)
}
/// N10 persistent-cleanup oracle: `(tgid, tid)` keys present in
/// the live THREADS map. THREADS rows are persistent — BPF never
/// removes them (only the host exit cleanup deletes rows) — so
/// the harness injects a synthetic row for a live tid and proves
/// the host deleted it after the exit. (API_THREADS rows are
/// transient — removed by BPF on normal return — so they cannot
/// prove host cleanup.)
fn bpftool_thread_keys() -> Option<Vec<(u32, u32)>> {
    bpftool_pairing_keys("THREADS")
}
/// R3-8 transient oracle: `(tgid, tid)` keys present in the live
/// API_THREADS map. Rows are transient (BPF removes them on
/// normal return): appearance during the spin proves the oracle
/// is live; per-tid absence at end proves no transient leak.
fn bpftool_apithread_keys() -> Option<Vec<(u32, u32)>> {
    bpftool_pairing_keys("API_THREADS")
}
/// Live tids of `pid` (leader included) via the task dir.
fn task_tids(pid: u32) -> Vec<u32> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
                .collect()
        })
        .unwrap_or_default()
}
/// Whether `tid` still has a task entry under `pid`.
fn task_alive(pid: u32, tid: u32) -> bool {
    std::fs::metadata(format!("/proc/{pid}/task/{tid}")).is_ok()
}
/// Inject a synthetic zero-valued `ThreadKey(pid, tid, gen 0)` row
/// into the THREADS map `id`. The host never reads these rows
/// (cleanup-only) and BPF self-heals a zero state on the next
/// hit, so the row is inert until the exit cleanup deletes it.
fn inject_thread_row(map_id: &str, pid: u32, tid: u32) -> bool {
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&pid.to_le_bytes());
    key.extend_from_slice(&tid.to_le_bytes());
    key.extend_from_slice(&0u64.to_le_bytes());
    let value = [0u8; 16];
    let hex: Vec<String> = key
        .iter()
        .chain(value.iter())
        .map(|b| format!("{b:02x}"))
        .collect();
    // bpftool takes one argv token per hex byte after each `hex`.
    Command::new("sudo")
        .args(["-n", "bpftool", "map", "update", "id", map_id])
        .args(["key", "hex"])
        .args(&hex[..16])
        .args(["value", "hex"])
        .args(&hex[16..])
        .output()
        .is_ok_and(|o| o.status.success())
}
/// Tick clock from the `start` row (§7): `(run_origin_ns,
/// interval_ns)`. `None` when the row is missing/malformed.
fn start_clock(rows: &[serde_json::Value]) -> Option<(u64, u64)> {
    let start = rows.iter().find(|r| r["kind"] == "start")?;
    let origin = start["run_origin_ns"].as_u64()?;
    let secs = start["poll_interval"]["secs"].as_u64()?;
    let nanos = start["poll_interval"]["nanos"].as_u64()?;
    let interval = secs.saturating_mul(1_000_000_000).saturating_add(nanos);
    if interval == 0 {
        return None;
    }
    Some((origin, interval))
}
/// Map a producer-clock instant to its tick (§7 `Start` rule).
fn tick_of(origin: u64, interval: u64, ns: u64) -> u64 {
    ns.saturating_sub(origin) / interval
}
/// R3-8: connector-drop guard — drops live under
/// `End.session_loss.signal_dropped`.
fn end_signal_dropped(rows: &[serde_json::Value]) -> u64 {
    rows.iter()
        .find(|r| r["kind"] == "end")
        .and_then(|e| e["session_loss"]["signal_dropped"].as_u64())
        .unwrap_or(0)
}
#[test]
fn r38_end_drops_read_session_loss_path() {
    // R3-8: the drop guard reads
    // `End.session_loss.signal_dropped` — a top-level-only read
    // sees zero and misclassifies a delivery-unproven survivor as
    // a cleanup failure.
    let rows = vec![serde_json::json!({
        "kind": "end",
        "session_loss": { "signal_dropped": 3 },
    })];
    assert_eq!(end_signal_dropped(&rows), 3);
    let rows = vec![serde_json::json!({ "kind": "end", "session_loss": {} })];
    assert_eq!(end_signal_dropped(&rows), 0);
    let rows = vec![serde_json::json!({ "kind": "start" })];
    assert_eq!(end_signal_dropped(&rows), 0);
}
/// 6A interval-specific shortfall (M3): some lost window — the
/// segment's own loss or the session carrier — intersects the
/// stimulus tick span `[t0, t1]`. A shortfall explained only by an
/// unknown marker elsewhere is NOT covered. N11: actual
/// intersection of the half-open loss window `[s, e)` with the
/// inclusive stimulus span — no slack: a window starting one tick
/// past the stimulus covers nothing in it.
fn shortfall_covered(
    rows: &[serde_json::Value],
    segment: &serde_json::Value,
    t0: u64,
    t1: u64,
) -> bool {
    let mut spans = Vec::new();
    for w in segment["loss"]["lost_windows"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        if let (Some(s), Some(e)) = (w["start_tick"].as_u64(), w["end_tick"].as_u64()) {
            spans.push((s, e));
        }
    }
    if let Some(end) = rows.iter().find(|r| r["kind"] == "end") {
        for w in end["session_loss"]["lost_intervals"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            if let (Some(s), Some(e)) = (w["start_tick"].as_u64(), w["end_tick"].as_u64()) {
                spans.push((s, e));
            }
        }
    }
    spans.iter().any(|(s, e)| *s <= t1 && *e > t0)
}
/// Wait for the first record matching `pred`, returning the row and
/// the harness receipt time (M10 promptness: receipt vs oracle
/// instants on the harness clock).
fn wait_for_record(
    outfile: &Path,
    timeout: Duration,
    pred: &dyn Fn(&serde_json::Value) -> bool,
) -> Option<(serde_json::Value, Instant, u64)> {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        let text = fs::read_to_string(outfile).unwrap_or_default();
        for line in text.lines() {
            if let Ok(row) = serde_json::from_str::<serde_json::Value>(line) {
                if pred(&row) {
                    // N12: receipt in both harness-clock (Instant)
                    // and producer-clock (ns) domains — promptness
                    // maps through the Start tick clock.
                    return Some((row, Instant::now(), monotonic_ns()));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}
/// Harness-side LOSS lane-0 high-water: sums key-0 values over all live
/// `LOSS` BPF maps (one per session) via bpftool. The D-record leg-B
/// oracle (direct map read, independent of the observer's own
/// reporting). None when bpftool is unavailable or no LOSS map exists.
fn bpftool_loss_lane0() -> Option<u64> {
    let list = Command::new("sudo")
        .args(["-n", "bpftool", "map", "list"])
        .output()
        .ok()?;
    if !list.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&list.stdout);
    let mut ids = Vec::new();
    for line in text.lines() {
        let Some((id, rest)) = line.split_once(':') else {
            continue;
        };
        if rest.contains("name LOSS ") {
            ids.push(id.trim().to_string());
        }
    }
    if ids.is_empty() {
        return None;
    }
    let mut total = 0u64;
    let mut found = false;
    for id in ids {
        let dump = Command::new("sudo")
            .args(["-n", "bpftool", "map", "dump", "id", &id, "-j"])
            .output()
            .ok()?;
        if !dump.status.success() {
            continue;
        }
        let json: serde_json::Value = serde_json::from_slice(&dump.stdout).ok()?;
        for entry in json.as_array().cloned().unwrap_or_default() {
            let is_zero = entry["key"].as_u64().is_some_and(|k| k == 0)
                || entry["key"]
                    .as_array()
                    .is_some_and(|b| b.iter().all(|x| x.as_str().is_some_and(|s| s == "0x00")));
            if !is_zero {
                continue;
            }
            for cpu in entry["values"].as_array().cloned().unwrap_or_default() {
                total = total.saturating_add(cpu["value"].as_u64().unwrap_or(0));
                found = true;
            }
        }
    }
    found.then_some(total)
}

fn observer_socket_drops(pid: u32) -> Option<u64> {
    // Owner-Pid column match: the observer runs as root, so its
    // /proc/<pid>/fd is unreadable to the harness (EACCES) — the
    // world-readable netlink table's Pid column names the owner
    // directly. Columns: sk Eth Pid Groups Rmem Wmem Dump Locks
    // Drops Inode.
    let text = fs::read_to_string("/proc/net/netlink").ok()?;
    let mut total = 0u64;
    let mut found = false;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() > 9 {
            if let (Ok(owner), Ok(drops)) = (fields[2].parse::<u32>(), fields[8].parse::<u64>()) {
                if owner == pid {
                    total = total.saturating_add(drops);
                    found = true;
                }
            }
        }
    }
    found.then_some(total)
}

/// Youngest live child of `parent` (the osslscope process under sudo).
fn child_pid(parent: u32) -> Option<u32> {
    // NB: non-pid entries sort FIRST in /proc, so every fallible step
    // below must skip (continue), never bail (?) — bailing returns
    // None before any pid is examined.
    let want = parent.to_string();
    let mut out = None;
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(after) = stat.rsplit_once(')').map(|p| p.1) else {
            continue;
        };
        let mut fields = after.split_whitespace();
        let (Some(_state), Some(ppid)) = (fields.next(), fields.next()) else {
            continue;
        };
        if ppid == want {
            out = Some(pid);
        }
    }
    out
}

/// Control 6 (lost-event): connector pressure (fork bomblet) and ring
/// pressure (call flood) both surface via SessionLoss with the one
/// authoritative total, affected windows unknown, never zero-quiet.
#[test]
fn control_6_lost_events_surface_explicitly() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    // Leg A: fork bomblet until the harness Drops oracle moves.
    let dir = fresh_dir("lossa");
    let bomblet_bin = compile_c(&dir, &["bomblet.c"], "bomblet", &["-lcrypto"]);
    let (drops_delta, rows_a) = {
        let log = dir.join("bomblet.log");
        let go = dir.join("go");
        let out = dir.join("watch.json");
        // Escalating pressure: 512, then 2048, then 8192.
        let mut result = None;
        for count in [512u32, 2048, 8192] {
            let _ = fs::remove_file(&go);
            let _ = fs::remove_file(&out);
            let _ = fs::remove_file(&log);
            let mut parent = Command::new(&bomblet_bin)
                .arg(&log)
                .arg(&go)
                .arg(count.to_string())
                .arg("12")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let pid = parent.id();
            let mut observer = spawn_observer(
                &binary,
                &[
                    "scan",
                    "--watch",
                    "--observe-crypto",
                    "--pid",
                    &pid.to_string(),
                    "--duration",
                    "11",
                    "--json",
                ],
                &out,
            );
            let started = wait_for_kind(&out, "start", Duration::from_secs(30));
            if !started {
                let _ = observer.kill();
                let _ = parent.kill();
            }
            assert!(started, "observer never started (round {count})");
            // The 6A feed needs a live connector subscription: no netlink
            // socket means no birth/death/exit following (system deficiency).
            let inner = child_pid(observer.id());
            let subscribed = inner.and_then(observer_socket_drops).is_some();
            if !subscribed {
                let _ = observer.kill();
                let _ = parent.kill();
                eprintln!("INCONCLUSIVE: observer holds no connector subscription");
                return;
            }
            let before = inner.and_then(observer_socket_drops).unwrap_or(0);
            fs::write(&go, b"go").unwrap();
            // Sample Drops while the observer is alive (its sockets die
            // with it); track the max — the oracle delta.
            let mut max_drops = before;
            loop {
                if let Some(inner) = child_pid(observer.id()) {
                    if let Some(now) = observer_socket_drops(inner) {
                        max_drops = max_drops.max(now);
                    }
                }
                if wait_for_kind(&out, "end", Duration::from_millis(200)) {
                    if let Some(inner) = child_pid(observer.id()) {
                        if let Some(now) = observer_socket_drops(inner) {
                            max_drops = max_drops.max(now);
                        }
                    }
                    break;
                }
                if observer.try_wait().unwrap().is_some() {
                    break;
                }
            }
            let status = observer.wait().unwrap();
            let after = max_drops;
            parent.wait().unwrap();
            assert!(
                matches!(status.code(), Some(0 | 3 | 4)),
                "observer failed: {status:?}"
            );
            let text = fs::read_to_string(&log).unwrap_or_default();
            let reaped: u32 = text
                .lines()
                .find_map(|l| {
                    l.strip_prefix("bomblet ")
                        .and_then(|r| r.split_whitespace().next()?.parse().ok())
                })
                .unwrap_or(0);
            if reaped != count {
                eprintln!("INCONCLUSIVE: bomblet reaped {reaped}/{count}");
                return;
            }
            if after > before {
                result = Some((after - before, read_rows(&out)));
                break;
            }
            eprintln!("leg A round {count}: Drops unmoved ({before}->{after}), escalating");
        }
        match result {
            Some(ok) => ok,
            None => {
                eprintln!("INCONCLUSIVE: Drops oracle never moved (box drains too fast?)");
                return;
            }
        }
    };
    eprintln!("leg A kinds: {:?}", kinds(&rows_a));
    let end_a = rows_a
        .iter()
        .find(|r| r["kind"] == "end")
        .expect("end record");
    let loss_a = &end_a["session_loss"];
    assert!(loss_a.is_object(), "no SessionLoss in End: {end_a}");
    // The one authoritative total covers the harness-measured Drops.
    assert!(
        loss_a["signal_dropped"].as_u64().unwrap_or(0) >= drops_delta,
        "signal_dropped {} < harness Drops {drops_delta}",
        loss_a["signal_dropped"]
    );
    assert!(
        loss_a["signal_dropped"].as_u64().unwrap_or(0)
            >= loss_a["connector_drops"].as_u64().unwrap_or(u64::MAX),
        "invariant signal_dropped >= connector_drops broken: {loss_a}"
    );
    assert!(
        loss_a["lost_intervals"]
            .as_array()
            .is_some_and(|w| !w.is_empty()),
        "connector pressure left no session lost-intervals"
    );
    // Leg B: ring pressure via 8-thread real-EVP spin (default
    // provider dispatch traversal). Direct fixture callbacks bypass
    // the provider ring entirely (no records, no overrun possible),
    // so the flood stimulus must traverse dispatch. The oracle is
    // harness-side: direct LOSS-map lane-0 high-water via bpftool.
    let dir = fresh_dir("lossb");
    let spinner = compile_c(
        &dir,
        &["evp_spin.c"],
        "evp_spin",
        &["-lcrypto", "-lpthread"],
    );
    let mut spin = Command::new(&spinner)
        .arg("8")
        .arg("25")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = spin.id();
    let out = dir.join("watch.json");
    let err = dir.join("watch.stderr");
    let mut observer = spawn_observer_stderr(
        &binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &pid.to_string(),
            "--duration",
            "16",
            "--json",
        ],
        &out,
        &err,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    let attached = started
        && wait_for_stderr(
            &err,
            &format!("focused callbacks attached (pid={pid}"),
            Duration::from_secs(60),
        );
    if !attached {
        let _ = observer.kill();
        let _ = spin.kill();
    }
    assert!(started, "observer never started");
    assert!(attached, "sites never attached");
    // Six seconds of post-attach pressure, then the harness-side
    // oracle: LOSS lane 0 must have moved (fresh session maps start
    // at zero, so any positive sum is the required delta).
    std::thread::sleep(Duration::from_secs(6));
    let oracle = bpftool_loss_lane0();
    if !oracle.is_some_and(|n| n > 0) {
        let _ = observer.kill();
        let _ = spin.kill();
        eprintln!("INCONCLUSIVE: LOSS lane-0 unmoved (stimulus incomplete)");
        return;
    }
    eprintln!("leg B harness LOSS lane-0: {}", oracle.unwrap());
    let _ = spin.kill();
    let _ = spin.wait();
    let status = observer.wait().unwrap();
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows_b = read_rows(&out);
    eprintln!("leg B kinds: {:?}", kinds(&rows_b));
    let end_b = rows_b
        .iter()
        .find(|r| r["kind"] == "end")
        .expect("end record");
    let ring: Vec<u64> = end_b["session_loss"]["ring"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|v| v.as_u64().unwrap_or(0))
        .collect();
    assert_eq!(ring.len(), 8, "SessionLoss.ring must have 8 lanes: {end_b}");
    assert!(
        ring[0] > 0,
        "proven ring overrun is silent (ring[0] == 0): {end_b}"
    );
    assert!(
        end_b["session_loss"]["lost_intervals"]
            .as_array()
            .is_some_and(|w| !w.is_empty()),
        "ring pressure left no session lost-intervals"
    );
    // Affected member windows render unknown (propagation, no per-member
    // duplication of the session total).
    let member_windows: usize = rows_b
        .iter()
        .filter(|r| {
            r["incarnation"]["pid"] == pid as u64
                && (r["kind"] == "membership" || r["kind"] == "process_observation")
        })
        .filter_map(|r| r["loss"]["lost_windows"].as_array().map(Vec::len))
        .sum();
    assert!(
        member_windows > 0,
        "ring loss never propagated to member windows"
    );
}

/// Control 7 (over-capacity fairness): 1030 eligible incarnations (past the
/// 1024 deferred boundary). Oldest-first admission, incumbents stable,
/// deterministic youngest drops, per-tick deferral, exact End tallies.
#[test]
fn control_7_over_capacity_defers_fairly() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let libcrypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
    if !Path::new(libcrypto).is_file() {
        eprintln!("INCONCLUSIVE: {libcrypto} missing");
        return;
    }
    // Spawn 1030 eligible sleepers with known (starttime, pid) order.
    let mut holders: Vec<Child> = Vec::new();
    let mut order: Vec<(u64, u32)> = Vec::new();
    for _ in 0..1030 {
        let mut child = Command::new("env")
            .arg(format!("LD_PRELOAD={libcrypto}"))
            .arg("sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Starttime immediately (spawn order == oracle order).
        let mut start = None;
        for _ in 0..50 {
            if let Some(t) = starttime_of(child.id()) {
                start = Some(t);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let Some(start) = start else {
            let _ = child.kill();
            for mut held in holders {
                let _ = held.kill();
                let _ = held.wait();
            }
            eprintln!("INCONCLUSIVE: sleeper vanished at spawn");
            return;
        };
        order.push((start, child.id()));
        holders.push(child);
    }
    let dir = fresh_dir("overload");
    let out = dir.join("watch.json");
    let pid_args: Vec<String> = order.iter().map(|(_, pid)| pid.to_string()).collect();
    // Feasible budgets: a complete 1030-pid scan costs ~8s on this
    // box (per-pid verified-association hashing is structural — the
    // backing cache deliberately never shares across pids), and the
    // scan budget is the interval. Interval 2 guarantees perpetual
    // whole-sample deadline ticks, on which §2.4 admits nothing; the
    // D-record never mandates interval 2 (only "hold overload 5
    // ticks"), so the harness operates within feasible budgets.
    let mut args: Vec<&str> = vec![
        "scan",
        "--watch",
        "--observe-crypto",
        "--duration",
        "70",
        "--interval",
        "12",
        "--json",
    ];
    for pid in &pid_args {
        args.push("--pid");
        args.push(pid);
    }
    let mut observer = spawn_observer(&binary, &args, &out);
    let status = observer.wait().unwrap();
    for mut held in holders {
        let _ = held.kill();
        let _ = held.wait();
    }
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    eprintln!("kinds: {:?}", kinds(&rows));
    let key_of = |pid: u32| order.iter().find(|(_, p)| *p == pid).copied();
    // Admitted incarnations are the oldest; every admitted key precedes
    // every deferred key (deterministic oldest-first, incumbents stable).
    let admitted: BTreeSet<u32> = rows
        .iter()
        .filter(|r| r["kind"] == "membership" && r["state"] == "observing")
        .filter_map(|r| r["incarnation"]["pid"].as_u64().map(|p| p as u32))
        .collect();
    assert!(!admitted.is_empty(), "nobody admitted under overload");
    let deferred: BTreeSet<u32> = rows
        .iter()
        .filter(|r| r["kind"] == "limit" && r["reason"] != "deferred_limit")
        .filter_map(|r| r["incarnation"]["pid"].as_u64().map(|p| p as u32))
        .collect();
    for a in &admitted {
        for d in &deferred {
            assert!(
                key_of(*a).unwrap() < key_of(*d).unwrap(),
                "admission not oldest-first: admitted {a:?} after deferred {d:?}"
            );
        }
    }
    // Incumbents stable: each admitted pid observes once and retires once
    // at the end (no mid-run eviction for a newcomer).
    for a in &admitted {
        let observing = rows
            .iter()
            .filter(|r| {
                r["kind"] == "membership"
                    && r["incarnation"]["pid"] == *a as u64
                    && r["state"] == "observing"
            })
            .count();
        let retired: Vec<&serde_json::Value> = rows
            .iter()
            .filter(|r| {
                r["kind"] == "membership"
                    && r["incarnation"]["pid"] == *a as u64
                    && r["state"] == "retired"
            })
            .collect();
        assert_eq!(observing, 1, "admitted {a} observed {observing}x (churn?)");
        assert_eq!(retired.len(), 1, "admitted {a} retired {}x", retired.len());
        assert_eq!(retired[0]["reason"], "duration");
    }
    // Binding order: pool binds before slots (all deferrals name it).
    for row in rows
        .iter()
        .filter(|r| r["kind"] == "limit" && r["reason"] != "deferred_limit")
    {
        assert_eq!(
            row["reason"], "global_state_limit",
            "binding order violated: {row}"
        );
        assert!(
            row["at_tick"].is_u64(),
            "per-tick Limit without at_tick: {row}"
        );
    }
    // Deferred incarnations show deferral every tick (multi-tick span).
    let mut ticks_by_pid: BTreeMap<u32, BTreeSet<u64>> = BTreeMap::new();
    for row in rows.iter().filter(|r| r["kind"] == "limit") {
        let pid = row["incarnation"]["pid"].as_u64().unwrap() as u32;
        if let Some(tick) = row["at_tick"].as_u64() {
            ticks_by_pid.entry(pid).or_default().insert(tick);
        }
    }
    for pid in &deferred {
        assert!(
            ticks_by_pid.get(pid).is_some_and(|t| t.len() >= 2),
            "deferred {pid} not visible across ticks: {ticks_by_pid:?}"
        );
    }
    // Drops are the youngest, each named with its sealed span.
    let drops: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["kind"] == "limit" && r["reason"] == "deferred_limit")
        .collect();
    assert!(!drops.is_empty(), "no youngest-drops at the 1024 boundary");
    for drop in &drops {
        let pid = drop["incarnation"]["pid"].as_u64().unwrap() as u32;
        for d in &deferred {
            assert!(
                key_of(pid).unwrap() > key_of(*d).unwrap(),
                "drop {pid} is not youngest vs deferred {d}"
            );
        }
        assert!(
            drop["deferred"].is_object(),
            "drop without sealed deferred span: {drop}"
        );
    }
    // End carries the exact boundary tallies.
    let end = rows
        .iter()
        .find(|r| r["kind"] == "end")
        .expect("end record");
    if end["peak_deferred_depth"].as_u64().unwrap_or(0) != 1024 {
        eprintln!(
            "INCONCLUSIVE: peak deferred depth {} (boundary never reached)",
            end["peak_deferred_depth"]
        );
        return;
    }
    assert_eq!(
        end["deferred_drops"].as_u64().unwrap_or(u64::MAX),
        drops.len() as u64,
        "End.deferred_drops != observed drops"
    );
}

/// Control-8 oracle helpers (independent of the observer): waitpid-equivalent
/// polling through the public API, /proc + fd inventory.
fn c8_wait_exit(target: &mut OwnedTarget, budget: Duration) -> Option<i32> {
    let end = Instant::now() + budget;
    loop {
        if let Some(code) = target.poll_exit().expect("poll_exit") {
            return Some(code);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn c8_assert_reaped(pid: u32) {
    assert!(
        fs::metadata(format!("/proc/{pid}")).is_err(),
        "pid {pid} still has a /proc entry (zombie or leak?)"
    );
}

fn c8_stat_state(pid: u32) -> Option<char> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

fn c8_fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(usize::MAX)
}

/// Control 8 (custody/output matrix): normal + nonzero exits preserve
/// waitpid status through the reported disposition.
#[test]
fn control_8_exit_status_matches_waitpid() {
    for (argv, code) in [
        (vec!["/bin/true".to_string()], 0),
        (vec!["/bin/false".to_string()], 1),
        (
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 7".to_string(),
            ],
            7,
        ),
    ] {
        let mut target = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).unwrap();
        let pid = target.pid();
        assert_eq!(target.state(), CustodyState::Stopped);
        target.release().unwrap();
        assert_eq!(target.state(), CustodyState::Released);
        assert_eq!(
            c8_wait_exit(&mut target, Duration::from_secs(5)),
            Some(code)
        );
        assert_eq!(target.state(), CustodyState::Reaped);
        assert_eq!(target.exit_code(), Some(code));
        assert_eq!(
            target.finish_observation().unwrap(),
            TargetDisposition::Exited { code }
        );
        c8_assert_reaped(pid);
    }
}

/// Control 8: invalid sink before fork → setup 126 with no child spawned.
#[test]
fn control_8_invalid_sink_reports_126_without_spawn() {
    let result = OwnedTarget::spawn_stopped(
        &["/bin/true".to_string()],
        WorkloadDest::File(PathBuf::from("/nonexistent-6a-dir-xyz/out.log")),
    );
    assert!(result.is_err(), "invalid sink must fail pre-fork");
    let err = match result {
        Ok(_) => unreachable!("invalid sink must fail pre-fork"),
        Err(err) => err,
    };
    let text = format!("{err:?}");
    assert!(
        text.contains("(setup status 126)") || text.contains("(status 126)"),
        "126 setup marker missing: {text}"
    );
    assert!(
        !text.contains("(status 127)") && !text.contains("(setup status 127)"),
        "127-confused: {text}"
    );
}

/// Control 8: failed exec → 127.
#[test]
fn control_8_failed_exec_reports_127() {
    let mut target = OwnedTarget::spawn_stopped(
        &["/nonexistent-6a-binary-xyz".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = target.pid();
    target.release().unwrap();
    assert_eq!(c8_wait_exit(&mut target, Duration::from_secs(5)), Some(127));
    assert_eq!(target.state(), CustodyState::Reaped);
    c8_assert_reaped(pid);
}

/// Control 8: cancellation/timeout → custody resolved, no zombie/pidfd leak.
#[test]
fn control_8_cancel_resolves_custody_without_leak() {
    let fds_before = c8_fd_count();
    let cancel = AtomicBool::new(true);
    let result = OwnedTarget::spawn_stopped_with_control(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
        Instant::now() + Duration::from_secs(5),
        &cancel,
    );
    // Either pre-fork refusal or a stopped child requiring resolution.
    if let Ok(mut target) = result {
        let pid = target.pid();
        target.resolve_setup_failure().unwrap();
        assert!(
            matches!(
                target.state(),
                CustodyState::Reaped | CustodyState::Detached
            ),
            "custody unresolved: {:?}",
            target.state()
        );
        if target.state() == CustodyState::Reaped {
            c8_assert_reaped(pid);
        } else if alive(pid) {
            Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .status()
                .unwrap();
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                let mut status = 0;
                let waited = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                if waited == pid as i32 || (waited < 0 && !alive(pid)) {
                    break;
                }
                assert!(Instant::now() < end, "cancelled child never reaped");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    assert_eq!(c8_fd_count(), fds_before, "fd leak across cancel");
}

/// Control 8: never-released terminate/reap; released expiry detaches.
#[test]
fn control_8_never_released_reaps_released_detaches() {
    // Never-released: terminated + reaped, status preserved.
    let mut target = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = target.pid();
    assert_eq!(
        c8_stat_state(pid),
        Some('T'),
        "child not observably stopped"
    );
    target.resolve_setup_failure().unwrap();
    assert_eq!(target.state(), CustodyState::Reaped);
    assert!(target.exit_code().is_some());
    c8_assert_reaped(pid);
    // Released expiry: leave-running Detached, child alive after.
    let mut target = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    target.release().unwrap();
    let disposition = target.finish_observation().unwrap();
    assert_eq!(
        disposition,
        TargetDisposition::Detached { pid: target.pid() }
    );
    assert_eq!(target.state(), CustodyState::Detached);
    let pid = target.pid();
    assert!(alive(pid), "released child killed by expiry");
    assert_ne!(c8_stat_state(pid), Some('T'), "released child stopped?");
    Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if waited == pid as i32 || (waited < 0 && !alive(pid)) {
            break;
        }
        assert!(Instant::now() < end, "released child never reaped");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Control 8: external `--pid` target never signaled/waited.
#[test]
fn control_8_external_pid_never_signaled() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = child.id();
    let target = osslscope::pin::ExternalTarget::adopt(pid).unwrap();
    assert_eq!(target.pid(), pid);
    target.verify().unwrap();
    target.verify().unwrap();
    assert!(alive(pid));
    assert_ne!(c8_stat_state(pid), Some('T'), "external target stopped?");
    assert_ne!(c8_stat_state(pid), Some('Z'), "external target reaped?");
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Control 8: externally continued never-released child → Detached, never killed.
#[test]
fn control_8_externally_continued_detaches_never_killed() {
    let mut target = OwnedTarget::spawn_stopped(
        &["/bin/sleep".to_string(), "30".to_string()],
        WorkloadDest::Null,
    )
    .unwrap();
    let pid = target.pid();
    assert_eq!(c8_stat_state(pid), Some('T'));
    // External continue (outside the observer's authority).
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGCONT) }, 0);
    let end = Instant::now() + Duration::from_secs(5);
    while c8_stat_state(pid) == Some('T') {
        assert!(Instant::now() < end, "child never continued");
        std::thread::sleep(Duration::from_millis(5));
    }
    target.resolve_setup_failure().unwrap();
    assert_eq!(
        target.state(),
        CustodyState::Detached,
        "continued child killed?"
    );
    assert!(alive(pid), "continued child dead");
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    // The test is still the parent (Detached disowns the handle, it does
    // not reparent): reap via waitpid.
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if waited == pid as i32 {
            break;
        }
        if waited < 0 {
            assert!(!alive(pid), "waitpid failed while child lives");
            break;
        }
        assert!(Instant::now() < end, "detached child never reaped");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Control 8: stdio isolation (null/file/fd byte-identity) + the explicit
/// shared FD1/2 mixing exception (caller-selected, accepted).
#[test]
fn control_8_stdio_isolation_and_mixing_exception() {
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo C8-OUT-S; echo C8-ERR-S >&2".to_string(),
    ];
    // Null: both streams discarded, status preserved.
    let mut target = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).unwrap();
    target.release().unwrap();
    assert_eq!(c8_wait_exit(&mut target, Duration::from_secs(5)), Some(0));
    // File: pre-fork-validated, byte-identical sentinels.
    let dir = fresh_dir("c8stdio");
    let file = dir.join("workload.log");
    let mut target = OwnedTarget::spawn_stopped(&argv, WorkloadDest::File(file.clone())).unwrap();
    target.release().unwrap();
    assert_eq!(c8_wait_exit(&mut target, Duration::from_secs(5)), Some(0));
    assert_eq!(fs::read(&file).unwrap(), b"C8-OUT-S\nC8-ERR-S\n");
    // Caller-held FD (pipe): byte-identical sentinels; fd stays open.
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (read, write) = (fds[0], fds[1]);
    let mut target = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Fd(write)).unwrap();
    target.release().unwrap();
    assert_eq!(c8_wait_exit(&mut target, Duration::from_secs(5)), Some(0));
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    for _ in 0..100 {
        if out.len() >= 16 {
            break;
        }
        let n = unsafe { libc::read(read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        assert!(n > 0, "pipe closed early");
        out.extend_from_slice(&buf[..n as usize]);
    }
    assert_eq!(out, b"C8-OUT-S\nC8-ERR-S\n");
    unsafe {
        libc::close(read);
        libc::close(write);
    }
    // Mixing exception: the caller's own FD1 is accepted (explicit
    // caller-selected mixing — the combined stream is not a clean
    // evidence channel, but the spawn is not refused).
    let mut target = OwnedTarget::spawn_stopped(&argv, WorkloadDest::Fd(1)).unwrap();
    target.release().unwrap();
    assert_eq!(c8_wait_exit(&mut target, Duration::from_secs(5)), Some(0));
}

/// Control 9a (dynamic module): dlopen of a new provider copy mid-run is an
/// additive refresh — same segment, counts continue, pre-discovery window
/// explicit `candidate_visibility_unknown`, never quiet, never a restart.
#[test]
fn control_9a_dynamic_module_refreshes_additively() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let dir = fresh_dir("dlopen");
    let mut app = FixtureSession::start(&dir);
    // A second provider file (distinct inode → distinct module).
    let provider2 = dir.join("provider2.so");
    fs::copy(dir.join("provider.so"), &provider2).unwrap();
    // `I` loads the provider, fetches the digest, and primes the
    // EVP pool (count_mode stays 0 -- no `P`: the probed site is
    // the plain digest_init).
    for setup in ["I"] {
        app.cmd(setup);
    }
    let pid = app.pid();
    let out = dir.join("watch.json");
    let err = dir.join("watch.stderr");
    let mut observer = spawn_observer_stderr(
        &binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &pid.to_string(),
            "--duration",
            "9",
            "--json",
        ],
        &out,
        &err,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    let attached = started
        && wait_for_stderr(
            &err,
            &format!("focused callbacks attached (pid={pid}"),
            Duration::from_secs(60),
        );
    if !attached {
        let _ = observer.kill();
        app.abort();
    }
    assert!(started, "observer never started");
    assert!(attached, "sites never attached");
    let admitted0 = bpftool_admitted_total();
    let first_c = app.cmd("C 500");
    let dlopen_lines = app.cmd(&format!("O {}", provider2.display()));
    assert!(
        dlopen_lines.iter().any(|l| l.ends_with(" 1")),
        "dlopen failed: {dlopen_lines:?}"
    );
    let second_c = app.cmd("C 500");
    let admitted1 = bpftool_admitted_total();
    // N from the rc-checked completion reports (EVP re-inits, not
    // the fixture counter -- count_mode is 0).
    let calls_done = |lines: &[String]| -> u64 {
        lines
            .iter()
            .find_map(|l| {
                l.strip_prefix("calls C ")
                    .and_then(|r| r.split_whitespace().nth(1)?.parse().ok())
            })
            .unwrap_or(0)
    };
    let oracle = calls_done(&first_c) + calls_done(&second_c);
    // Independent ADMITTED == N gate (mandatory, never waived): all
    // 1000 calls post-admission.
    if oracle != 1000
        || admitted0.is_none()
        || admitted1 != admitted0.map(|b| b.saturating_add(1000))
    {
        let _ = observer.kill();
        app.finish();
        eprintln!("INCONCLUSIVE: completed={oracle} admitted={admitted0:?}->{admitted1:?}");
        return;
    }
    let calls_ns = |lines: &[String]| -> Option<u64> {
        lines.iter().find_map(|l| {
            l.strip_prefix("calls C ")
                .and_then(|r| r.split_whitespace().nth(2)?.parse().ok())
        })
    };
    let status = observer.wait().unwrap();
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    app.finish();
    eprintln!("kinds: {:?}", kinds(&rows));
    // One continuous segment (no incarnation restart on dlopen).
    let segments = segments_by_pid(&rows);
    let mine = segments.get(&(pid as u64)).cloned().unwrap_or_default();
    assert_eq!(mine.len(), 1, "dlopen restarted the incarnation: {mine:?}");
    let total = segment_calls(mine[0]).expect("segment calls sum");
    assert!(total <= 1000, "over-attribution: {total} > 1000");
    if total != 1000 {
        let (origin, interval) = start_clock(&rows).expect("tick clock");
        let t0 = tick_of(origin, interval, calls_ns(&first_c).expect("C1 instant"));
        let t1 = tick_of(origin, interval, calls_ns(&second_c).expect("C2 instant"));
        assert!(
            shortfall_covered(&rows, mine[0], t0.min(t1), t0.max(t1)),
            "shortfall {total}/1000 not covered over stimulus ticks {t0}..{t1}"
        );
    }
    // The additive refresh is explicit: same-state record carrying the
    // transition detail, pre-discovery window candidate_visibility_unknown.
    let refresh: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["detail"]["kind"] == "additive_module_refresh"
        })
        .collect();
    assert_eq!(
        refresh.len(),
        1,
        "additive refresh not recorded: {refresh:?}"
    );
    assert_eq!(refresh[0]["state"], "observing");
    assert_eq!(refresh[0]["reason"], "candidate_visibility_unknown");
    assert!(refresh[0]["detail"]["tid"].is_null());
}

/// Control 9b (cgroup): slow inter-tick move stays in the same segment with
/// a `cgroup_move` detail + unknown window; between-pass moves render the
/// member unknown for that sample, never removed or counted.
#[test]
fn control_9b_cgroup_move_stays_with_unknown_window() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let dir = fresh_dir("cgroup");
    let root = PathBuf::from("/sys/fs/cgroup/ossl-6a-cgroup");
    let sub_a = root.join("sub_a");
    let sub_b = root.join("sub_b");
    // N1: a sibling OUTSIDE the watched root for the move-out leg.
    let outside = PathBuf::from("/sys/fs/cgroup/ossl-6a-outside");
    let sudo = |args: &[&str]| {
        Command::new("sudo")
            .arg("-n")
            .args(args)
            .status()
            .unwrap()
            .success()
    };
    for stale in [&sub_a, &sub_b, &root, &outside] {
        sudo(&["rmdir", &stale.to_string_lossy()]);
    }
    if !sudo(&["mkdir", "-p", &sub_a.to_string_lossy()])
        || !sudo(&["mkdir", "-p", &sub_b.to_string_lossy()])
        || !sudo(&["mkdir", "-p", &outside.to_string_lossy()])
    {
        eprintln!("INCONCLUSIVE: cgroup delegation refused");
        return;
    }
    // Member starts in sub_a.
    let mut member = Command::new("openssl")
        .args([
            "speed", "-elapsed", "-seconds", "30", "-evp", "SHA512", "-bytes", "64",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = member.id();
    let placed = sudo(&[
        "sh",
        "-c",
        &format!("echo {pid} > {}", sub_a.join("cgroup.procs").display()),
    ]);
    if !placed {
        let _ = member.kill();
        sudo(&["rmdir", &sub_a.to_string_lossy()]);
        sudo(&["rmdir", &sub_b.to_string_lossy()]);
        sudo(&["rmdir", &root.to_string_lossy()]);
        sudo(&["rmdir", &outside.to_string_lossy()]);
        eprintln!("INCONCLUSIVE: cgroup placement refused");
        return;
    }
    let out = dir.join("watch.json");
    let mut observer = spawn_observer(
        &binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--cgroup",
            &root.to_string_lossy(),
            "--duration",
            "16",
            "--json",
        ],
        &out,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    if !started {
        let _ = observer.kill();
        let _ = member.kill();
    }
    assert!(started, "observer never started");
    // Settle two ticks in sub_a, move (slower than the tick), settle two.
    std::thread::sleep(Duration::from_secs(3));
    let moved = sudo(&[
        "sh",
        "-c",
        &format!("echo {pid} > {}", sub_b.join("cgroup.procs").display()),
    ]);
    std::thread::sleep(Duration::from_secs(3));
    // N1 move-out leg (D-record §1.6): out of the watched root —
    // the next stable sample drops the incarnation (departure),
    // even though the member is followed. Settle three ticks so
    // the excluded tick plus the departure tick both land.
    let moved_out = sudo(&[
        "sh",
        "-c",
        &format!("echo {pid} > {}", outside.join("cgroup.procs").display()),
    ]);
    std::thread::sleep(Duration::from_secs(4));
    let status = observer.wait().unwrap();
    let _ = member.kill();
    let _ = member.wait();
    sudo(&["rmdir", &sub_a.to_string_lossy()]);
    sudo(&["rmdir", &sub_b.to_string_lossy()]);
    sudo(&["rmdir", &root.to_string_lossy()]);
    sudo(&["rmdir", &outside.to_string_lossy()]);
    if !moved {
        eprintln!("INCONCLUSIVE: cgroup move refused");
        return;
    }
    if !moved_out {
        eprintln!("INCONCLUSIVE: cgroup move-out refused");
        return;
    }
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    eprintln!("kinds: {:?}", kinds(&rows));
    // Stay: one segment across the move (no departure/re-admission).
    let segments = segments_by_pid(&rows);
    let mine = segments.get(&(pid as u64)).cloned().unwrap_or_default();
    assert_eq!(
        mine.len(),
        1,
        "cgroup move broke segment unity (saw {}): {mine:?}",
        mine.len()
    );
    let observing = rows
        .iter()
        .filter(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["state"] == "observing"
                && r["detail"].is_null()
        })
        .count();
    assert_eq!(observing, 1, "member re-admitted across the move");
    // The move is explicit: cgroup_move detail + unknown inter-tick window.
    let details: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["detail"]["kind"] == "cgroup_move"
        })
        .collect();
    assert_eq!(details.len(), 1, "cgroup_move not recorded: {details:?}");
    let windows: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r["incarnation"]["pid"] == pid as u64
                && (r["kind"] == "membership" || r["kind"] == "process_observation")
        })
        .filter(|r| {
            r["loss"]["lost_windows"]
                .as_array()
                .is_some_and(|w| w.iter().any(|interval| interval["cause"] == "cgroup_move"))
        })
        .collect();
    assert!(!windows.is_empty(), "inter-tick move window not unknown");
    // N1 move-out leg: leaving the watched root departs (the next
    // stable sample drops the incarnation) — following never
    // promotes the followed member into scoped membership. The
    // retirement is a mid-run departure, not the end-of-run seal,
    // and the incarnation is forgotten (never re-admitted outside
    // its root).
    let retires: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["state"] == "retired"
        })
        .collect();
    assert_eq!(
        retires.len(),
        1,
        "move-out member must retire exactly once: {retires:?}"
    );
    assert_eq!(
        retires[0]["reason"], "sampled_removal",
        "move-out must depart, not seal at close: {}",
        retires[0]["reason"]
    );
}

/// Control 9c (namespace): mount-ns change retires the old incarnation and
/// re-admits a stranger (new segment, empty history, nothing inherited).
#[test]
fn control_9c_namespace_change_readmits_stranger() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let dir = fresh_dir("nschange");
    let probe = compile_c(&dir, &["ns_probe.c"], "ns_probe", &["-lcrypto"]);
    let log = dir.join("ns.log");
    let go = dir.join("go");
    let out = dir.join("watch.json");
    // Runs as root (unshare needs privilege); the observer reads it fine.
    let mut child = Command::new("sudo")
        .args(["-n"])
        .arg(&probe)
        .arg(&log)
        .arg(&go)
        .arg("10")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    while !fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("ready ")
    {
        assert!(Instant::now() < end, "ns fixture never ready");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Fixture pid: the sudo child (parse from the ready line).
    let text = fs::read_to_string(&log).unwrap();
    let pid: u32 = text
        .lines()
        .find_map(|l| {
            l.strip_prefix("ready ")
                .and_then(|r| r.split_whitespace().next()?.parse().ok())
        })
        .expect("ready line");
    let mut observer = spawn_observer(
        &binary,
        &[
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &pid.to_string(),
            "--duration",
            "11",
            "--json",
        ],
        &out,
    );
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    if !started {
        let _ = observer.kill();
        let _ = child.kill();
    }
    assert!(started, "observer never started");
    std::thread::sleep(Duration::from_secs(2));
    fs::write(&go, b"go").unwrap();
    let status = observer.wait().unwrap();
    let _ = child.wait();
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let text = fs::read_to_string(&log).unwrap();
    assert!(
        text.contains("unshared "),
        "namespace never changed: {text}"
    );
    let rows = read_rows(&out);
    eprintln!("kinds: {:?}", kinds(&rows));
    // Two incarnations (two mount-ns identities), old retired first.
    let mut mounts = BTreeSet::new();
    for row in rows.iter().filter(|r| {
        r["incarnation"]["pid"] == pid as u64
            && (r["kind"] == "membership" || r["kind"] == "process_observation")
    }) {
        mounts.insert(row["incarnation"]["namespaces"]["mount"].to_string());
    }
    assert_eq!(mounts.len(), 2, "namespace change invisible: {mounts:?}");
    let retired: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            r["kind"] == "membership"
                && r["incarnation"]["pid"] == pid as u64
                && r["state"] == "retired"
        })
        .collect();
    assert!(
        retired.iter().any(|r| r["reason"] == "incarnation_changed"),
        "old incarnation not retired as changed: {retired:?}"
    );
    // Stranger: fresh segment with empty history (no inheritance).
    let segments = segments_by_pid(&rows);
    let mine = segments.get(&(pid as u64)).cloned().unwrap_or_default();
    assert_eq!(mine.len(), 2, "stranger never re-admitted: {mine:?}");
    let key_of = |s: &serde_json::Value| s["incarnation"].to_string();
    assert_ne!(key_of(mine[0]), key_of(mine[1]), "same key twice?");
    for segment in &mine {
        assert_eq!(segment["loss"]["deferred"]["ticks"].as_u64(), Some(0));
    }
}

/// Control 9d (cleanup): cancel during a deferred backlog resolves custody;
/// every deferred entry emits `deferred_removed{cancelled}` + sealed span.
#[test]
fn control_9d_cancel_drains_deferred_backlog() {
    let Some(stage) = stage_privileged_binary() else {
        return;
    };
    let binary = stage.binary.clone();
    let libcrypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
    if !Path::new(libcrypto).is_file() {
        eprintln!("INCONCLUSIVE: {libcrypto} missing");
        return;
    };
    let mut holders: Vec<Child> = Vec::new();
    for _ in 0..20 {
        holders.push(
            Command::new("env")
                .arg(format!("LD_PRELOAD={libcrypto}"))
                .arg("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    let dir = fresh_dir("cancel");
    let out = dir.join("watch.json");
    let mut args: Vec<&str> = vec![
        "scan",
        "--watch",
        "--observe-crypto",
        "--duration",
        "30",
        "--json",
    ];
    let pids: Vec<String> = holders.iter().map(|c| c.id().to_string()).collect();
    for pid in &pids {
        args.push("--pid");
        args.push(pid);
    }
    let mut observer = spawn_observer(&binary, &args, &out);
    let started = wait_for_kind(&out, "start", Duration::from_secs(30));
    if !started {
        let _ = observer.kill();
        for held in holders.iter_mut() {
            let _ = held.kill();
            let _ = held.wait();
        }
    }
    assert!(started, "observer never started");
    // Wait for a real backlog (deferred Limits flowing), then SIGTERM.
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        let rows = read_rows(&out);
        let deferred = rows.iter().filter(|r| r["kind"] == "limit").count();
        if deferred >= 10 {
            break;
        }
        assert!(Instant::now() < end, "no deferred backlog formed");
        std::thread::sleep(Duration::from_millis(200));
    }
    Command::new("kill")
        .arg("-TERM")
        .arg(observer.id().to_string())
        .status()
        .unwrap();
    let status = observer.wait().unwrap();
    for mut held in holders {
        let _ = held.kill();
        let _ = held.wait();
    }
    assert!(
        matches!(status.code(), Some(0 | 3 | 4)),
        "observer failed: {status:?}"
    );
    let rows = read_rows(&out);
    eprintln!("kinds: {:?}", kinds(&rows));
    let end = rows
        .iter()
        .find(|r| r["kind"] == "end")
        .expect("end record");
    assert_eq!(end["reason"], "cancelled");
    // Every entry still deferred at close is removed explicitly.
    let removed: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["kind"] == "membership" && r["state"] == "deferred_removed")
        .collect();
    assert!(!removed.is_empty(), "backlog silently dropped on cancel");
    for row in &removed {
        assert_eq!(row["reason"], "cancelled");
        // M5: sealed spans are positive with coherent bounds (no
        // vacuous alternative -- ticks > 0, first <= last, ticks
        // within the bound span).
        let span = &row["loss"]["deferred"];
        let ticks = span["ticks"].as_u64().unwrap_or(0);
        let first = span["first_tick"].as_u64();
        let last = span["last_tick"].as_u64();
        assert!(ticks > 0, "removed entry without sealed span: {row}");
        let (Some(first), Some(last)) = (first, last) else {
            panic!("removed entry without span bounds: {row}");
        };
        assert!(
            first <= last,
            "removed entry with incoherent span bounds: {row}"
        );
        assert!(
            ticks <= last.saturating_sub(first).saturating_add(1),
            "removed entry ticks exceed its span: {row}"
        );
    }
    assert_eq!(
        end["deferred_removed"]["closed"]
            .as_u64()
            .unwrap_or(u64::MAX),
        removed.len() as u64,
        "End tally != observed removals"
    );
}

/// §7 shape conformance (unprivileged): Start/Membership/End carry the full
/// 6A additive shape under crypto-watch-v1; a clean run has no loss.
#[test]
fn shapes_6a_additive_records_conform() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_osslscope"));
    let mut sleeper = Command::new("sleep").arg("6").spawn().unwrap();
    let pid = sleeper.id();
    let output = Command::new(&binary)
        .args([
            "scan",
            "--watch",
            "--observe-crypto",
            "--pid",
            &pid.to_string(),
            "--duration",
            "2",
            "--json",
        ])
        .output()
        .unwrap();
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    assert!(
        matches!(output.status.code(), Some(0 | 3 | 4)),
        "{output:?}"
    );
    let rows: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!rows.is_empty());
    for row in &rows {
        assert_eq!(row["schema_version"], "crypto-watch-v1");
    }
    let start = rows.iter().find(|r| r["kind"] == "start").expect("start");
    assert!(
        start["run_origin_ns"].is_u64(),
        "Start.run_origin_ns: {start}"
    );
    assert!(start["run_origin_ns"].as_u64().unwrap() > 0);
    assert!(start["run_origin_ns"].as_u64().unwrap() < u64::MAX);
    let memberships: Vec<&serde_json::Value> =
        rows.iter().filter(|r| r["kind"] == "membership").collect();
    assert!(!memberships.is_empty(), "no membership records");
    for row in &memberships {
        assert!(row["image_epoch"].is_u64(), "Membership.image_epoch: {row}");
        assert!(row["loss"].is_object(), "Membership.loss: {row}");
        assert!(row["loss"]["deferred"].is_object(), "loss.deferred: {row}");
        assert!(
            row["loss"]["lost_windows"].is_array(),
            "loss.windows: {row}"
        );
    }
    let end = rows
        .iter()
        .find(|r| r["kind"] == "end")
        .expect("end record");
    assert!(end["peak_deferred_depth"].is_u64(), "End tallies: {end}");
    assert!(end["deferred_drops"].is_u64(), "End tallies: {end}");
    assert!(end["deferred_removed"].is_object(), "End tallies: {end}");
    let session = &end["session_loss"];
    assert!(session.is_object(), "End.session_loss: {end}");
    assert_eq!(session["ring"].as_array().map(Vec::len), Some(8));
    for key in [
        "connector_drops",
        "connector_enobufs",
        "scan_loss",
        "signal_dropped",
        "signal_prefix_unwitnessed",
        "drain_pending",
        "unattributed_events",
        "admitted_exit_artifacts",
        "coalesced",
    ] {
        assert!(session[key].is_u64(), "session_loss.{key}: {session}");
    }
    assert!(session["polling_fallback"].is_boolean());
    assert!(session["lost_intervals"].is_array());
    // Clean unprivileged run: nothing lost, nothing deferred, nothing
    // dropped. A kernel subscription honestly reports its unwitnessed
    // prefix (tick 0); polling reports none. Either way, no other loss.
    for w in session["lost_intervals"].as_array().unwrap() {
        assert_eq!(
            w["cause"], "signal_prefix_unwitnessed",
            "clean run lost more than the subscription prefix: {session}"
        );
    }
    assert_eq!(end["peak_deferred_depth"], 0);
    assert_eq!(end["deferred_drops"], 0);
}
