//! SPDX-License-Identifier: GPL-3.0-or-later
//! P5d: first-call cold gap on ONE exact pinned build.
//!
//! Vehicle: system `openssl` CLI 3.5.5-1ubuntu3.7 (Ubuntu
//! 3.5.5-1ubuntu3.7 — binary + libcrypto sha256 asserted below). Workload:
//! `openssl speed -seconds 1 aes-128-cbc` (pristine one-shot-ish run,
//! no injected queries/sleeps/modifications; the pre-exec SIGSTOP hold
//! is fork-level, the executed image is untouched).
//!
//! Live legs (ignored; `OSSL_P5D_LIVE=1 OSSL_P5D_OBJECT=<harvest .o>`
//! (+ `OSSL_P5D_COUNT_OBJECT=<count .o>` for the capture leg)):
//! birth-attach (spawn-held-stopped, SIGCONT after attaches install)
//! vs cold-attach (release, sleep `OSSL_P5D_DELAY_MS`, then attach).
//! The birth-minus-cold delta IS the measured cold gap: missed query
//! executions enumerated per op (CALLS-joined), startup-gap reasons
//! assigned. `OSSL_P5D_LEGACY=1` toggles the legacy trip plane.
//!
//! Legs: `birth_speed_harvest` (full-run birth reference),
//! `cold_speed_harvest` (delayed attach), `birth_dgst_harvest`
//! (fifo-held one-shot — cold-attach infeasible, spawn-only),
//! `birth_dgst_free_running_rows` (P6 §6ii close-join proof),
//! `capture_spawn_counts_executions` (P6 counting contract).
//! Plus one offline unit test (per-op conservation).
//!
//! Live legs MUST run with `--test-threads=1`: the orphan backstop
//! attributes new process children to the running leg, which is
//! sound only when one leg runs at a time.

use osslscope::discovery::harvest::{self, Config, HarvestTotals};
use osslscope::target::{OwnedTarget, WorkloadDest};
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Pinned vehicle identity (Ubuntu 3.5.5-1ubuntu3.7, debian-amd64).
const VEHICLE_BIN: &str = "/usr/bin/openssl";
const VEHICLE_SHA256: &str = "1d72cbc5bf62be3f3dbd7626c295b63c5fdc1dd8439f323ac47998d8a062b4c9";
const VEHICLE_VERSION_MARK: &str = "3.5.5";
const LIBCRYPTO: &str = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
const LIBCRYPTO_SHA256: &str = "5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28";

/// Fixture uniqueness: temp-file names carry pid + tag + this seq so
/// parallel legs, reruns, and parallel test binaries never share one.
static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

fn gated() -> Option<PathBuf> {
    if std::env::var("OSSL_P5D_LIVE").unwrap_or_default() != "1" {
        eprintln!("p5d legs: set OSSL_P5D_LIVE=1; skipping");
        return None;
    }
    let object: PathBuf = std::env::var("OSSL_P5D_OBJECT")
        .expect("OSSL_P5D_OBJECT=<harvest BPF .o>")
        .into();
    assert!(object.is_file(), "harvest object missing: {object:?}");
    Some(object)
}

/// Assert the vehicle is the pinned build (exact bytes + version)
/// and the loader environment is pristine: an `LD_LIBRARY_PATH`
/// alternate (or `LD_PRELOAD` interposition) would silently
/// substitute the measured library, so fail closed instead.
fn assert_vehicle_pinned() {
    // `var_os().is_none()`: a non-Unicode value is still a value
    // (`var().is_err()` would misread NotUnicode as absence).
    assert!(
        std::env::var_os("LD_LIBRARY_PATH").is_none(),
        "refusing to measure under LD_LIBRARY_PATH (loader substitution risk)"
    );
    assert!(
        std::env::var_os("LD_PRELOAD").is_none(),
        "refusing to measure under LD_PRELOAD (interposition risk)"
    );
    let out = std::process::Command::new(VEHICLE_BIN)
        .arg("version")
        .output()
        .expect("vehicle runs");
    assert!(out.status.success(), "vehicle `openssl version` failed");
    let v = String::from_utf8_lossy(&out.stdout);
    assert!(
        v.contains(VEHICLE_VERSION_MARK),
        "vehicle version drift: {v:?}"
    );
    let bytes = std::fs::read(VEHICLE_BIN).expect("read vehicle");
    let digest = sha256_hex(&bytes);
    assert_eq!(digest, VEHICLE_SHA256, "vehicle binary drift");
    let lib_bytes = std::fs::read(LIBCRYPTO).expect("read libcrypto");
    let lib_digest = sha256_hex(&lib_bytes);
    assert_eq!(lib_digest, LIBCRYPTO_SHA256, "libcrypto drift");
    // NOTE: the anchor rung verifies the SUPPLIED file's bytes, not
    // what the child maps — mapped identity is gated separately per
    // leg (`mapped_libcrypto_ok`), plus the loader-env gate above.
    eprintln!("p5d: vehicle pinned ({v:?}trimmed, both shas ok)");
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn workload_argv() -> Vec<String> {
    [VEHICLE_BIN, "speed", "-seconds", "1", "aes-128-cbc"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Guarded enrollment fixture for the pinned build (runbook rung
/// 2): offsets measured from the dbgsym twin (same build-id
/// 0ebcfe..., verified via `readelf -n`):
/// `ossl_provider_query_operation` @ 0x275390, anchor
/// `OSSL_PROVIDER_available` @ 0x275190 (both inside the R E
/// PT_LOAD, file offset == vaddr). Unique path per leg (never a
/// shared pid-named file), removed on drop.
struct EnrollmentTable {
    path: PathBuf,
}

impl EnrollmentTable {
    fn create(tag: &str) -> Self {
        let seq = FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "p5d-table-{}-{}-{}.json",
            std::process::id(),
            tag,
            seq
        ));
        let content = r#"{"table_version": 1,
    "entries": [{"build_id": "0ebcfeaee273dc860b29e067d255def704185b41",
      "openssl": "3.5.5-1ubuntu3.7",
      "query_offset": 2577296,
      "anchor": "OSSL_PROVIDER_available",
      "anchor_offset": 2576784}]}"#;
        std::fs::write(&path, content).expect("write enrollment table");
        Self { path }
    }

    fn path(&self) -> PathBuf {
        self.path.clone()
    }
}

impl Drop for EnrollmentTable {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Conservation: per-op query counts must sum to the total. Both
/// totals come from the same join (CALLS-joined per-op high-water
/// when the map exists, accepted QUERY_RET events otherwise), so a
/// healthy run conserves exactly; a failed (partial) map read is
/// the only legitimate source of sum > total (its failure flag
/// records snapshot loss).
fn conservation_ok(t: &HarvestTotals) -> bool {
    t.queries_by_op.iter().map(|(_, n)| n).sum::<u64>() == t.queries_observed
}

#[test]
fn per_op_counts_conserve() {
    let t = HarvestTotals {
        queries_observed: 73,
        queries_by_op: vec![(2, 10), (12, 60), (14, 3)],
    };
    assert!(conservation_ok(&t));
    let bad = HarvestTotals {
        queries_observed: 73,
        queries_by_op: vec![(2, 10)],
    };
    assert!(!conservation_ok(&bad));
    assert!(conservation_ok(&HarvestTotals::default()));
}

/// Child-death check WITHOUT reaping: the pin guard verifies
/// starttime at close, and a reaped child fails it as "recycled".
/// A zombie still has /proc/PID/stat (state Z) with intact
/// starttime, so stop on Z/X/missing but reap only after close.
fn child_dead_noreap(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
    match stat {
        Err(_) => true,
        Ok(s) => s
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|st| st == "Z" || st == "X" || st == "x"),
    }
}

/// RAII custody for a spawned leg child: a bare `.expect()` before
/// manual cleanup would orphan a released child on the error path
/// (`OwnedTarget::Drop` deliberately leaves it running), so the
/// guard SIGKILLs + reaps a still-live child on drop — covering
/// success, error, and unwind paths uniformly. Drop never panics
/// (a panic during unwind would abort); it reports loudly instead.
struct ChildGuard<'a> {
    target: &'a RefCell<OwnedTarget>,
}

impl ChildGuard<'_> {
    /// Natural-exit gate: the child must have exited 0 on its own.
    /// A SIGKILLed, crashed, or otherwise incomplete run is never
    /// an accepted measurement. Call after observation completes
    /// (the guard itself only guarantees no orphan, not validity).
    fn require_natural_exit(&self, what: &str) {
        match self.target.borrow_mut().poll_exit() {
            Ok(Some(0)) => {}
            other => panic!("{what}: child did not exit 0 naturally: {other:?}"),
        }
    }

    /// Intentional scaffold kill (fifo-held legs only): the child is
    /// deliberately kept alive through observation and killed after
    /// the measurement completes. Returns the exit code (must be
    /// 128+SIGKILL — anything else means the scaffold died on its
    /// own, invalidating the hold). The Drop backstop no-ops after
    /// this (already reaped).
    fn kill_scaffold(&self, what: &str) -> i32 {
        let mut t = self.target.borrow_mut();
        if let Ok(Some(code)) = t.poll_exit() {
            panic!("{what}: scaffold exited on its own ({code}) — hold failed");
        }
        let pid = t.pid();
        let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        assert_eq!(r, 0, "{what}: scaffold SIGKILL failed");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match t.poll_exit() {
                Ok(Some(code)) => return code,
                Ok(None) => {}
                Err(e) => panic!("{what}: scaffold reap failed: {e:?}"),
            }
            if Instant::now() >= deadline {
                panic!("{what}: scaffold survived SIGKILL");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard<'_> {
    fn drop(&mut self) {
        let mut t = self.target.borrow_mut();
        match t.poll_exit() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(e) => {
                eprintln!("guard: poll failed ({e:?}); killing anyway");
            }
        }
        let pid = t.pid();
        let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if r != 0 {
            eprintln!("guard: SIGKILL {pid} failed, attempting reap anyway");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(t.poll_exit(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        eprintln!("guard: child {pid} survived SIGKILL (LEAKED)");
    }
}

/// Orphan backstop for child lifetimes the test holds no handle to:
/// `capture::run` owns its child internally and may detach it live
/// on salvage paths (the observer never kills a running
/// application) — a capture error or a failed assertion after the
/// run would then leak a running workload. Snapshots this
/// process's children at arming; on drop, SIGKILLs + reaps any
/// child that appeared since. Sound only under `--test-threads=1`
/// (see module docs). Drop never panics, but every degraded path
/// reports loudly — a leak must never escape silently.
struct OrphanGuard {
    before: Vec<i32>,
    blind_at_arm: bool,
}

impl OrphanGuard {
    fn arm() -> Self {
        let (before, failures) = process_children();
        let blind = failures > 0;
        if blind {
            eprintln!(
                "orphan-guard: ARM DEGRADED ({failures} enumeration failures) — \
                 leak detection is best-effort for this leg"
            );
        }
        Self {
            before,
            blind_at_arm: blind,
        }
    }
}

impl Drop for OrphanGuard {
    fn drop(&mut self) {
        let (current, failures) = process_children();
        if self.blind_at_arm || failures > 0 {
            eprintln!(
                "orphan-guard: enumeration unhealthy (arm-blind={} drop-failures={failures}) — \
                 the sweep below may be incomplete",
                self.blind_at_arm
            );
        }
        for pid in current {
            if self.before.contains(&pid) {
                continue;
            }
            eprintln!("orphan-guard: reclaiming leaked child {pid}");
            let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            if r != 0 {
                let e = std::io::Error::last_os_error();
                // ESRCH: already gone (possibly a zombie) — the reap
                // attempt below still applies. Any other signal
                // error is reported, not ignored.
                if e.raw_os_error() != Some(libc::ESRCH) {
                    eprintln!("orphan-guard: SIGKILL {pid} failed: {e}");
                }
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                // Deadline first: every retry path (EINTR spins
                // included) terminates — no unbounded continue.
                if Instant::now() >= deadline {
                    eprintln!("orphan-guard: child {pid} survived SIGKILL (LEAKED)");
                    break;
                }
                let mut status = 0;
                let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
                if r == pid as libc::pid_t {
                    break;
                }
                if r < 0 {
                    let e = std::io::Error::last_os_error();
                    match e.raw_os_error() {
                        Some(x) if x == libc::EINTR => continue,
                        // Reaped elsewhere (e.g. the harness won the
                        // race): the desired end state, nothing leaked.
                        Some(x) if x == libc::ECHILD => {
                            eprintln!("orphan-guard: {pid} already reaped");
                            break;
                        }
                        _ => {
                            eprintln!("orphan-guard: waitpid {pid} failed: {e} (UNRESOLVED)");
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// This process's children (union over all threads' `children`
/// files — process children are shared; one live thread's file
/// suffices, the union is robust to thread churn). Returns the
/// names plus an enumeration-failure count: callers must REPORT a
/// nonzero count (a silent empty/incomplete list would let a leak
/// escape without a diagnostic).
fn process_children() -> (Vec<i32>, usize) {
    let mut out = Vec::new();
    let mut failures = 0;
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return (out, 1);
    };
    for entry in tasks {
        // Directory-entry errors are enumeration failures too: a
        // silently dropped entry would let a leak escape with a
        // clean zero-failure report.
        let Ok(t) = entry else {
            failures += 1;
            continue;
        };
        let Ok(s) = std::fs::read_to_string(t.path().join("children")) else {
            // Usually thread churn (exited between readdir and
            // read); counted either way so the sweep is explicit.
            failures += 1;
            continue;
        };
        out.extend(s.split_whitespace().filter_map(|x| x.parse::<i32>().ok()));
    }
    out.sort_unstable();
    out.dedup();
    (out, failures)
}

/// Mapped-identity gate: the anchor rung verifies the SUPPLIED
/// file, not what the child maps. Attaching against a pinned-but-
/// unmapped file would read zero queries as a 100% gap, so fail
/// closed unless the child's mapped libcrypto IS the pinned file.
/// Compares VMA-RECORDED (device, inode) — never the pathname's
/// current metadata (a maps snapshot describing an old inode must
/// not pass after its pathname resolves to a pinned replacement) —
/// with both sides in the SAME domain: the child's recorded pair
/// against this process's own mapping of the pinned file (mmap'd
/// here, so its maps line carries the pinned identity in maps
/// encoding). Same-domain comparison is REQUIRED, not stylistic:
/// on this box (btrfs) maps records 00:22 while stat reports dev
/// 36 for the same file (verified box-systematic on libc too), so
/// any maps-vs-stat device comparison misfires. The device rides
/// the repository's descriptor domain (`plan::encode_device`).
/// A fresh file-content hash closes in-place modification between
/// leg start and the gate. COLD-LEG ONLY: birth legs assert
/// queries_observed > 0, and the query probes are pid-scoped +
/// file-bound (installed pre-exec), so observed queries already
/// prove the pinned bytes executed — a substituted library yields
/// zero queries and fails the assert (fail-closed). A post-release
/// maps gate in birth legs would additionally race a 10ms child
/// (zombie maps read empty) for zero added proof.
fn mapped_libcrypto_ok(pid: u32) -> anyhow::Result<()> {
    // Fresh content pin (TOCTOU: the file must still be the pinned
    // bytes at gate time, not just at leg start).
    let fresh = std::fs::read(LIBCRYPTO)?;
    anyhow::ensure!(
        sha256_hex(&fresh) == LIBCRYPTO_SHA256,
        "pinned libcrypto bytes changed mid-run"
    );
    // The exe link flips before the loader maps libcrypto — wait
    // for the mapping (bounded), else a fast child fails spuriously.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        if maps.lines().any(|l| {
            l.rsplit_once(' ')
                .map(|(_, p)| p)
                .unwrap_or("")
                .ends_with("libcrypto.so.3")
        }) {
            break;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("child {pid}: libcrypto.so.3 never mapped");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let child_id = recorded_maps_identity(pid, None)?;
    let mine = recorded_maps_identity(std::process::id(), Some(PinnedMapping::map()?))?;
    anyhow::ensure!(
        child_id == mine,
        "child {pid} maps a different libcrypto: \
         recorded {child_id:?} vs pinned {mine:?}"
    );
    Ok(())
}

/// RAII one-page private mapping of the pinned file (provides a
/// same-domain maps line for identity comparison).
struct PinnedMapping {
    addr: *mut libc::c_void,
}

impl PinnedMapping {
    fn map() -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd as _;
        let f = std::fs::File::open(LIBCRYPTO)?;
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                f.as_raw_fd(),
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            anyhow::bail!(
                "mmap pinned libcrypto failed: {:?}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Self { addr })
    }

    fn addr(&self) -> u64 {
        self.addr as u64
    }
}

impl Drop for PinnedMapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.addr, 4096);
        }
    }
}

/// VMA-recorded (encode_device, inode) for a libcrypto mapping of
/// `pid`: the first one, or (when `must_contain` is set) the one
/// containing that address. Fail-closed on parse errors.
fn recorded_maps_identity(
    pid: u32,
    must_contain: Option<PinnedMapping>,
) -> anyhow::Result<(u64, u64)> {
    let want_addr = must_contain.as_ref().map(|m| m.addr());
    // Keep the mapping alive for the whole read (it must still be
    // mapped when /proc/self/maps is sampled below).
    let _keep = must_contain;
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (addr_range, dev, ino) = match (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) {
            (Some(a), Some(_), Some(_), Some(d), Some(i)) => (a, d, i),
            _ => anyhow::bail!("pid {pid}: unparsable maps line"),
        };
        let path = fields.next().unwrap_or("");
        if !path.ends_with("libcrypto.so.3") {
            continue;
        }
        if let Some(want) = want_addr {
            let (lo, hi) = addr_range
                .split_once('-')
                .and_then(|(a, b)| {
                    u64::from_str_radix(a, 16)
                        .ok()
                        .zip(u64::from_str_radix(b, 16).ok())
                })
                .ok_or_else(|| anyhow::anyhow!("pid {pid}: unparsable maps range"))?;
            if !(lo <= want && want < hi) {
                continue;
            }
        }
        let (major, minor) = dev
            .split_once(':')
            .and_then(|(a, b)| {
                u32::from_str_radix(a, 16)
                    .ok()
                    .zip(u32::from_str_radix(b, 16).ok())
            })
            .ok_or_else(|| anyhow::anyhow!("pid {pid}: unparsable maps device {dev:?}"))?;
        let rec_ino: u64 = ino
            .parse()
            .map_err(|_| anyhow::anyhow!("pid {pid}: unparsable maps inode {ino:?}"))?;
        return Ok((osslscope::plan::encode_device(major, minor), rec_ino));
    }
    anyhow::bail!("pid {pid} maps no libcrypto.so.3")
}

fn harvest_cfg(pid: u32, object: PathBuf, table: PathBuf, birth: bool, settle: Duration) -> Config {
    let legacy = std::env::var("OSSL_P5D_LEGACY").unwrap_or_default() == "1";
    Config {
        pid,
        provider: PathBuf::from(LIBCRYPTO),
        object,
        // Settle is per-leg: multi-wave workloads need 30s (a 500ms
        // settle broke the speed drain mid-run), single-wave legs
        // use 500ms so the drain ends on post-wave quiet.
        settle,
        timeout: Duration::from_secs(90),
        cmdline_marker: None,
        builtin: true,
        legacy,
        table: Some(table),
        force_offset: None,
        observed_from_birth: birth,
    }
}

/// Birth leg: spawn-held-stopped, attach, SIGCONT only after every
/// attach is installed. Asserts the post-exec query wave is observed.
#[test]
#[ignore = "live lane only (OSSL_P5D_LIVE=1)"]
fn birth_speed_harvest() {
    let Some(object) = gated() else { return };
    assert_vehicle_pinned();
    let target = RefCell::new(
        OwnedTarget::spawn_stopped(&workload_argv(), WorkloadDest::Null)
            .expect("spawn held-stopped"),
    );
    let guard = ChildGuard { target: &target };
    let table = EnrollmentTable::create("birth-speed");
    let pid = target.borrow().pid();
    let cfg = harvest_cfg(pid, object, table.path(), true, Duration::from_secs(30));
    // Release, then wait for exec: the first drain poll reconciles
    // stage-2 against /proc maps, and pre-exec maps (the parent's)
    // would detach it as unmapped. Kernel-side observation starts
    // at attach (pre-exec), so the wait loses no coverage in the
    // ordinary case — with the caveat that ring buffering is
    // bounded, and a freakishly short exec could vanish between
    // /proc/exe polls (neither observed here: speed runs ~6s with
    // 2ms polls).
    let on_attached = || {
        target.borrow_mut().release()?;
        let exe = format!("/proc/{pid}/exe");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(link) = std::fs::read_link(&exe) {
                if link.to_string_lossy() == VEHICLE_BIN {
                    break;
                }
            }
            if Instant::now() > deadline {
                anyhow::bail!("child {pid} never exec'd {VEHICLE_BIN}");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // Then wait for libcrypto mapped OR child death (bounded):
        // the first drain poll detaches stage-2 TERMINALLY when
        // bindings are absent, so returning in the loader window
        // (exec'd, libcrypto not yet mapped) bails the run — a
        // 2ms-granularity exe poll usually lands past it, but luck
        // is not a gate. Post-mortem return is safe: the drain
        // breaks before polling and close joins the maps.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child_dead_noreap(pid) {
                break;
            }
            if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                if maps.lines().any(|l| {
                    l.rsplit_once(' ')
                        .map(|(_, p)| p)
                        .unwrap_or("")
                        .ends_with("libcrypto.so.3")
                }) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!("child {pid}: libcrypto.so.3 never mapped while alive");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // No mapped-identity gate here (see mapped_libcrypto_ok):
        // the pid-scoped, file-bound probes prove pinned execution
        // via queries_observed > 0, and a 10ms child may already be
        // a zombie (empty maps) at this point.
        Ok(())
    };
    let should_stop = || child_dead_noreap(pid);
    let (doc, totals) =
        harvest::run_detailed(&cfg, &on_attached, &should_stop).expect("birth harvest");
    guard.require_natural_exit("birth");
    eprintln!(
        "p5d birth: queries_observed={} by_op={:?} status={:?} reason={:?}",
        totals.queries_observed,
        totals.queries_by_op,
        doc.get("status"),
        doc.get("reason")
    );
    std::fs::write(
        "/tmp/p5d-birth.json",
        serde_json::to_string_pretty(&doc).unwrap(),
    )
    .unwrap();
    assert!(
        totals.queries_observed > 0,
        "birth attach saw zero queries — trigger doctrine broken?"
    );
    assert!(
        conservation_ok(&totals),
        "per-op counts don't sum to total: {:?} vs {}",
        totals.queries_by_op,
        totals.queries_observed
    );
}

/// Short one-shot birth leg: free-running `dgst` takes ~10ms —
/// far below the ~1.9s attach latency, so cold-attach can NEVER
/// observe it; spawn-mode pre-attach is the only path. The child
/// reads its (4KB) input from a test-held fifo so it stays alive
/// through observation: a free-running 10ms child races the drain
/// (close-path row loss on fast-dying targets — design §6(ii),
/// a P6 product fix), which would make this leg flaky for reasons
/// outside P5d. The fifo changes EOF TIMING
/// only: the measured startup query wave (init + fetch) is
/// delivery-independent, and the leg pins its exact counts.
/// Drain ends on post-wave settle (500ms — one wave, no later
/// queries); the scaffold is then SIGKILLed (asserted 128+SIGKILL,
/// never natural exit).
#[test]
#[ignore = "live lane only (OSSL_P5D_LIVE=1)"]
fn birth_dgst_harvest() {
    use std::io::Write as _;
    let Some(object) = gated() else { return };
    assert_vehicle_pinned();
    let seq = FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst);
    let fifo = std::env::temp_dir().join(format!("p5d-dgst-{}-{}.fifo", std::process::id(), seq));
    let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    let r = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
    assert_eq!(r, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
    // O_RDWR open never blocks (no reader/writer rendezvous) and
    // counts as its own reader, so the pre-release 4KB write below
    // buffers without SIGPIPE; the child's read-open then succeeds
    // and its post-4KB reads block until the scaffold kill.
    let mut writer = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fifo)
        .unwrap_or_else(|e| panic!("fifo open O_RDWR failed: {e:?}"));
    writer.write_all(&[0x5Au8; 4096]).expect("fifo prime write");
    writer.flush().expect("fifo flush");
    let argv = [VEHICLE_BIN, "dgst", "-sha256", fifo.to_str().unwrap()]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let target = RefCell::new(
        OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).expect("spawn held-stopped"),
    );
    let guard = ChildGuard { target: &target };
    let table = EnrollmentTable::create("birth-dgst");
    let pid = target.borrow().pid();
    let cfg = harvest_cfg(pid, object, table.path(), true, Duration::from_millis(500));
    let on_attached = || {
        target.borrow_mut().release()?;
        let exe = format!("/proc/{pid}/exe");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(link) = std::fs::read_link(&exe) {
                if link.to_string_lossy() == VEHICLE_BIN {
                    break;
                }
            }
            if Instant::now() > deadline {
                anyhow::bail!("child {pid} never exec'd {VEHICLE_BIN}");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // Then wait for libcrypto mapped OR child death (bounded):
        // the first drain poll detaches stage-2 TERMINALLY when
        // bindings are absent, so returning in the loader window
        // (exec'd, libcrypto not yet mapped) bails the run — luck
        // is not a gate. The death branch is vestigial under the
        // fifo hold (the child cannot exit while blocked on the
        // fifo) but keeps the wait total if the scaffold misbehaves.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child_dead_noreap(pid) {
                break;
            }
            if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                if maps.lines().any(|l| {
                    l.rsplit_once(' ')
                        .map(|(_, p)| p)
                        .unwrap_or("")
                        .ends_with("libcrypto.so.3")
                }) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!("child {pid}: libcrypto.so.3 never mapped while alive");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // No mapped-identity gate here (see mapped_libcrypto_ok):
        // the pid-scoped, file-bound probes prove pinned execution
        // via the exact-count asserts below.
        Ok(())
    };
    let should_stop = || child_dead_noreap(pid);
    let (doc, totals) =
        harvest::run_detailed(&cfg, &on_attached, &should_stop).expect("dgst harvest");
    // Drain ended on post-wave settle; the scaffold must still be
    // blocked on the fifo — kill it and assert the kill (a natural
    // exit means the hold failed and the measurement is void).
    let code = guard.kill_scaffold("dgst");
    assert_eq!(code, 128 + libc::SIGKILL, "dgst scaffold killed by test");
    drop(writer);
    let _ = std::fs::remove_file(&fifo);
    let rows = doc
        .get("rows")
        .and_then(|r| r.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    eprintln!(
        "p5d dgst birth: queries_observed={} by_op={:?} rows={} status={:?} reason={:?}",
        totals.queries_observed,
        totals.queries_by_op,
        rows,
        doc.get("status"),
        doc.get("reason")
    );
    std::fs::write(
        "/tmp/p5d-dgst.json",
        serde_json::to_string_pretty(&doc).unwrap(),
    )
    .unwrap();
    assert_eq!(
        totals.queries_observed, 2,
        "dgst startup wave must be exactly init + fetch"
    );
    assert_eq!(
        totals.queries_by_op,
        vec![(1u32, 2u64)],
        "dgst wave must be op 1 x2"
    );
    assert_eq!(rows, 174, "dgst walk must enumerate the same 174 tables");
    assert!(
        conservation_ok(&totals),
        "per-op counts don't sum: {:?} vs {}",
        totals.queries_by_op,
        totals.queries_observed
    );
}

/// Free-running one-shot rows leg (P6 §6ii close-join proof):
/// `dgst` on a 64KiB regular file exits ~10ms after release, so its
/// startup wave is still in the ring at close. Pre-fix, close()
/// counted the tail as shortfall without joining → 0 rows in 2/7
/// runs (specimen `drain_shortfall=193`, queries kept via CALLS).
/// Post-fix, close ingests the tail (bounded) and every run walks
/// the same 174 tables. Same exact asserts as the fifo leg; the
/// fifo leg pins the wave independent of death timing, this leg
/// pins close completeness under real death timing.
#[test]
#[ignore = "live lane only (OSSL_P5D_LIVE=1)"]
fn birth_dgst_free_running_rows() {
    let Some(object) = gated() else { return };
    assert_vehicle_pinned();
    let seq = FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst);
    let input =
        std::env::temp_dir().join(format!("p5d-dgstfree-{}-{}.bin", std::process::id(), seq));
    std::fs::write(&input, vec![0x5Au8; 65536]).unwrap();
    let argv = [VEHICLE_BIN, "dgst", "-sha256", input.to_str().unwrap()]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let target = RefCell::new(
        OwnedTarget::spawn_stopped(&argv, WorkloadDest::Null).expect("spawn held-stopped"),
    );
    let guard = ChildGuard { target: &target };
    let table = EnrollmentTable::create("birth-dgstfree");
    let pid = target.borrow().pid();
    let cfg = harvest_cfg(pid, object, table.path(), true, Duration::from_millis(500));
    let on_attached = || {
        target.borrow_mut().release()?;
        let exe = format!("/proc/{pid}/exe");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(link) = std::fs::read_link(&exe) {
                if link.to_string_lossy() == VEHICLE_BIN {
                    break;
                }
            }
            if Instant::now() > deadline {
                anyhow::bail!("child {pid} never exec'd {VEHICLE_BIN}");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // Then wait for libcrypto mapped OR child death (bounded):
        // the first drain poll detaches stage-2 TERMINALLY when
        // bindings are absent, so returning in the loader window
        // bails the run — luck is not a gate. Post-mortem return
        // is safe: the drain breaks before polling and close joins
        // the tail (this leg's whole point).
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child_dead_noreap(pid) {
                break;
            }
            if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                if maps.lines().any(|l| {
                    l.rsplit_once(' ')
                        .map(|(_, p)| p)
                        .unwrap_or("")
                        .ends_with("libcrypto.so.3")
                }) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                anyhow::bail!("child {pid}: libcrypto.so.3 never mapped while alive");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        // No mapped-identity gate here (see mapped_libcrypto_ok):
        // the pid-scoped, file-bound probes prove pinned execution
        // via the exact-count asserts below, and a 10ms child may
        // already be a zombie (empty maps) at this point.
        Ok(())
    };
    let should_stop = || child_dead_noreap(pid);
    let (doc, totals) =
        harvest::run_detailed(&cfg, &on_attached, &should_stop).expect("dgst-free harvest");
    guard.require_natural_exit("dgst-free");
    let _ = std::fs::remove_file(&input);
    let rows = doc
        .get("rows")
        .and_then(|r| r.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    eprintln!(
        "p5d dgst-free birth: queries_observed={} by_op={:?} rows={} status={:?} reason={:?}",
        totals.queries_observed,
        totals.queries_by_op,
        rows,
        doc.get("status"),
        doc.get("reason")
    );
    std::fs::write(
        "/tmp/p5d-dgst-free.json",
        serde_json::to_string_pretty(&doc).unwrap(),
    )
    .unwrap();
    assert_eq!(
        totals.queries_observed, 2,
        "dgst startup wave must be exactly init + fetch"
    );
    assert_eq!(
        totals.queries_by_op,
        vec![(1u32, 2u64)],
        "dgst wave must be op 1 x2"
    );
    assert_eq!(rows, 174, "close must join the tail: 174 tables every run");
    assert!(
        conservation_ok(&totals),
        "per-op counts don't sum: {:?} vs {}",
        totals.queries_by_op,
        totals.queries_observed
    );
}

/// Spawn-birth capture counts executions (P6: the redundant-ELF-parse
/// stall is fixed — discovery adapts in ms, count probes attach while
/// the workload still runs): a spawn-birth capture on the pinned
/// vehicle observes the query trigger and yields NON-EMPTY executions
/// with the attach census HELD (op sites discovered == attached,
/// objects present, child exit 0, non-fatal, zero cold_gap_calls).
/// (P5d pinned the zero-execution defect here: 10.2s of repeated
/// goblin parses stalled one apply_delta, landing count attach 7.5s
/// after the child exited. The fix memoizes build-ids per file.)
#[test]
#[ignore = "live lane only (OSSL_P5D_LIVE=1)"]
fn capture_spawn_counts_executions() {
    let Some(harvest_object) = gated() else {
        return;
    };
    let count_object: PathBuf = match std::env::var("OSSL_P5D_COUNT_OBJECT") {
        Ok(p) => p.into(),
        Err(_) => {
            eprintln!("capture leg: set OSSL_P5D_COUNT_OBJECT=<count .o>; skipping");
            return;
        }
    };
    assert_vehicle_pinned();
    // No owned handle exists for capture's child (it may detach
    // live on salvage paths), so arm the orphan backstop BEFORE
    // the run: it reclaims leaks on error, assert-failure, and
    // unwind paths alike.
    let _orphans = OrphanGuard::arm();
    let table = EnrollmentTable::create("capture-defect");
    let cfg = osslscope::capture::Config {
        harvest_object: Some(harvest_object),
        count_object: Some(count_object),
        provider: Some(PathBuf::from(LIBCRYPTO)),
        builtin: true,
        table: Some(table.path()),
        force_offset: None,
        provider_enrollment: None,
        resolved_provider: None,
        duration: Duration::from_secs(15),
        settle: Duration::from_secs(30),
        harvest_timeout: Duration::from_secs(30),
        grace: Duration::from_secs(5),
        image_digest: String::new(),
    };
    let t_entry = monotonic_ns();
    let cap = osslscope::capture::run(
        &cfg,
        osslscope::capture::Target::Spawn {
            argv: workload_argv(),
            workload: WorkloadDest::Null,
        },
    )
    .expect("spawn capture");
    let min_first = cap.executions.iter().map(|e| e.first_ns).min();
    let total_calls: u64 = cap.executions.iter().map(|e| e.count).sum();
    // Coverage + attachment census (the plane `empty-inventory`
    // cannot see): per-scope discovered/attached, fenced sites,
    // objects. P6's fix must move EXECUTIONS while HOLDING this
    // census (attach counts are already complete).
    let coverage: Vec<(String, String, u64, u64)> = cap
        .document
        .coverage
        .iter()
        .map(|c| {
            (
                c.scope.clone(),
                format!("{:?}", c.expected),
                c.discovered,
                c.attached,
            )
        })
        .collect();
    let fenced_sites: usize = cap.document.fenced.iter().map(|g| g.sites.len()).sum();
    eprintln!(
        "p5d capture: {} executions, {} calls, min_first-entry={:?}, outcome={:?} reasons={:?} child_exit={:?} counters={:?} coverage={:?} doc_sites={} fenced={} objects={}",
        cap.executions.len(),
        total_calls,
        min_first.map(|f| Duration::from_nanos(f.saturating_sub(t_entry))),
        cap.outcome,
        cap.reasons,
        cap.child_exit,
        [
            ("cold_gap", cap.counters.cold_gap_calls),
            ("dropped_bpf", cap.counters.dropped_bpf),
            ("dropped_userspace", cap.counters.dropped_userspace),
            ("missed_attaches", cap.counters.missed_attaches),
            ("drain_shortfall", cap.counters.drain_shortfall),
            ("uninstrumented", cap.counters.uninstrumented_ops),
            ("over_budget", cap.counters.over_budget),
        ],
        coverage,
        cap.document.sites.len(),
        fenced_sites,
        cap.document.objects.len(),
    );
    // Preserve the FULL document (sites/fenced/coverage/objects/
    // counters) — the `harvest_doc` stub (`rows: []` always) would
    // discard the census this leg characterizes.
    std::fs::write(
        "/tmp/p5d-capture.json",
        serde_json::to_string_pretty(&cap.document).unwrap(),
    )
    .unwrap();
    // Healthy-run gates: the workload exited 0 and capture stayed
    // non-fatal — the characterization below is about a completed
    // run, not a crash or a salvaged failure.
    assert_eq!(
        cap.child_exit,
        Some(0),
        "capture workload did not exit 0: {:?}",
        cap.child_exit
    );
    assert!(
        !matches!(cap.outcome, osslscope::capture::Outcome::Fatal(_)),
        "capture went fatal: {:?}",
        cap.outcome
    );
    assert!(
        cap.counters.cold_gap_calls == 0,
        "birth capture shows a cold gap: {}",
        cap.counters.cold_gap_calls
    );
    // Trigger gate: the count plane only observes post-trigger
    // executions, so a missing trigger voids the contract below.
    assert!(
        cap.harvest_doc.get("trigger_observed") == Some(&serde_json::Value::Bool(true)),
        "no query trigger observed — counting contract void"
    );
    // HELD census (attach counts complete) + COUNTING contract
    // (executions non-empty): every op scope attached exactly what
    // it discovered, at least one op site attached, objects present,
    // and the count plane observed real calls (no empty-inventory).
    let op_scopes: Vec<_> = cap
        .document
        .coverage
        .iter()
        .filter(|c| c.scope.starts_with("op:"))
        .collect();
    assert!(
        !op_scopes.is_empty(),
        "no op scopes in census: {coverage:?}"
    );
    for c in &op_scopes {
        assert_eq!(
            c.attached, c.discovered,
            "attach shortfall in {}: {coverage:?}",
            c.scope
        );
    }
    let op_attached: u64 = op_scopes.iter().map(|c| c.attached).sum();
    assert!(op_attached > 0, "zero attached op sites: {coverage:?}");
    assert!(!cap.document.objects.is_empty(), "zero objects in document");
    assert!(
        !cap.document.sites.is_empty(),
        "count plane observed no sites: executions={} reasons={:?} coverage={:?}",
        cap.executions.len(),
        cap.reasons,
        coverage
    );
    // Substantial-counting guard (~3.0M observed, 30× margin):
    // pins a heavily counted hot loop rather than a token trickle
    // or a zero collapse. It does not pin attach timing (an ~+3s
    // attach still cleared ~800K) — only that the plane counted
    // at scale — while tolerating timing variance.
    assert!(
        !cap.executions.is_empty() && total_calls > 100_000,
        "count plane counted too few calls: executions={} calls={} reasons={:?} coverage={:?}",
        cap.executions.len(),
        total_calls,
        cap.reasons,
        coverage
    );
    assert!(
        !cap.reasons.iter().any(|r| r == "empty-inventory"),
        "empty-inventory still raised with {} executions: {:?}",
        cap.executions.len(),
        cap.reasons
    );
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(r, 0, "clock_gettime failed");
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Cold leg: release immediately, sleep the delay, THEN attach.
/// Prints the observed post-attach queries + attach latency; the
/// cold gap is the birth-minus-cold delta (see evidence NOTES).
#[test]
#[ignore = "live lane only (OSSL_P5D_LIVE=1)"]
fn cold_speed_harvest() {
    let Some(object) = gated() else { return };
    assert_vehicle_pinned();
    let delay_ms: u64 = std::env::var("OSSL_P5D_DELAY_MS")
        .unwrap_or_default()
        .parse()
        .unwrap_or(1500);
    let target = RefCell::new(
        OwnedTarget::spawn_stopped(&workload_argv(), WorkloadDest::Null)
            .expect("spawn held-stopped"),
    );
    let guard = ChildGuard { target: &target };
    target.borrow_mut().release().expect("release");
    std::thread::sleep(Duration::from_millis(delay_ms));
    // Child must still be running (else the delay missed the workload).
    assert!(
        target.borrow_mut().poll_exit().unwrap().is_none(),
        "child exited before cold attach (delay {delay_ms}ms too long?)"
    );
    let pid = target.borrow().pid();
    // Mapped identity BEFORE attach: a zero-query return is a 100%
    // gap only when the child provably maps the pinned file.
    mapped_libcrypto_ok(pid).expect("mapped libcrypto identity");
    let table = EnrollmentTable::create("cold-speed");
    let cfg = harvest_cfg(pid, object, table.path(), false, Duration::from_secs(30));
    // Attach-latency timestamp: on_attached fires post-attach, so
    // t_fire - t_call bounds the install window inside the gap.
    let t_call = std::time::Instant::now();
    let attached_at = RefCell::new(None);
    let on_attached = || {
        *attached_at.borrow_mut() = Some(t_call.elapsed());
        Ok(())
    };
    let should_stop = || child_dead_noreap(pid);
    let (doc, totals) =
        harvest::run_detailed(&cfg, &on_attached, &should_stop).expect("cold harvest");
    guard.require_natural_exit("cold");
    // The attach hook MUST have fired: a blind return (zero queries)
    // is an honest measurement only when attach provably installed.
    // (Zero post-attach queries with a fired hook = 100% gap, valid.)
    assert!(
        attached_at.borrow().is_some(),
        "attach hook never fired — blind return is a broken run, not a measurement"
    );
    eprintln!(
        "p5d cold (delay {delay_ms}ms, attach {:?}): queries_observed={} by_op={:?} status={:?} reason={:?}",
        attached_at.borrow(),
        totals.queries_observed,
        totals.queries_by_op,
        doc.get("status"),
        doc.get("reason")
    );
    std::fs::write(
        "/tmp/p5d-cold.json",
        serde_json::to_string_pretty(&doc).unwrap(),
    )
    .unwrap();
    assert!(doc.get("status").is_some(), "cold doc lacks status");
    assert!(
        conservation_ok(&totals),
        "per-op counts don't sum to total: {:?} vs {}",
        totals.queries_by_op,
        totals.queries_observed
    );
}
