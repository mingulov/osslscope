//! SPDX-License-Identifier: GPL-3.0-or-later
//! §4 durable sequence and reset identity: state shapes, atomic
//! persistence, exclusive ownership.
//!
//! Two publication disciplines (§4.2): write-once evidence via
//! `link(2)` no-overwrite (`publish`), mutable state via
//! tmp+rename+fsync+dirsync (here). Recovery lives in `recovery`.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Schema words (§0 legend).
pub const SCHEMA_SEQ: &str = "service-seq-v1";
pub const SCHEMA_POLICY: &str = "service-policy-v1";
pub const SCHEMA_RUN: &str = "service-run-v1";
pub const SCHEMA_QUOTA_STOP: &str = "service-quota-stop-v1";
pub const SCHEMA_LOCK: &str = "service-lock-v1";

/// Reserved filenames (§4.1 alias admission).
pub const RESERVED_NAMES: &[&str] = &[
    "sequence.json",
    "policy-status.json",
    "run-summary.json",
    "quota-stop.json",
    "service.lock",
];

/// Attempt identity: pid + starttime + boot id (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunId {
    pub pid: u32,
    pub starttime: u64,
    pub boot_id: String,
}

impl RunId {
    /// Read this process's identity (starttime = `/proc/self/stat`
    /// field 22; boot id read once at startup).
    pub fn current() -> std::io::Result<Self> {
        let pid = std::process::id();
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let after = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
        let starttime = after
            .split_whitespace()
            .nth(19) // field 22 overall (post-comm token k = field k+3)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        Ok(Self {
            pid,
            starttime,
            boot_id,
        })
    }

    /// `run_id_tag` = `pid-starttime-boot8` (§4.2 tmp names).
    pub fn tag(&self) -> String {
        let boot8: String = self.boot_id.chars().take(8).collect();
        format!("{}-{}-{boot8}", self.pid, self.starttime)
    }
}

/// Reservation states (§0 legend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Open,
    Committed,
    Abandoned,
}

/// Abandonment reasons (§0 legend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbandonReason {
    Crash,
    CancelGraceExpiry,
    DiskFull,
    IoError,
    DoubleSignal,
    WorkerUnavailable,
    DirFsyncLost,
}

/// The attempt record (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Reservation {
    pub seq: u64,
    pub run_id: RunId,
    pub generation: u64,
    pub requested_start_ns: u64,
    pub requested_end_ns: u64,
    pub state: ReservationState,
    pub reason: Option<AbandonReason>,
    pub started: bool,
}

/// `sequence.json` (§4.3). Tolerant reads for 6C live in consumers;
/// the service writes the full shape.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SequenceState {
    pub schema: String,
    pub generation: u64,
    pub next_seq: u64,
    pub updated_wall_ns: u64,
    pub close_completed_ns: Option<u64>,
    pub exhausted: bool,
    pub run_id: RunId,
    pub reserved: Option<Reservation>,
}

impl SequenceState {
    pub fn fresh(run_id: RunId, now_wall_ns: u64) -> Self {
        Self {
            schema: SCHEMA_SEQ.to_string(),
            generation: 0,
            next_seq: 0,
            updated_wall_ns: now_wall_ns,
            close_completed_ns: None,
            exhausted: false,
            run_id,
            reserved: None,
        }
    }
}

/// Active/pending policy identity (§3 envelope note).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyIdentity {
    pub path: String,
    pub sha256: String,
    pub version: i64,
    pub rule_count: usize,
    pub adopted_seq: Option<u64>,
}

/// `policy-status.json` (§3 carrier).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyStatus {
    pub schema: String,
    pub active: Option<PolicyIdentity>,
    pub pending_valid: Option<PolicyIdentity>,
    pub pending_displaced: u64,
    pub last_rejection: Option<PolicyRejection>,
}

/// One recorded reload rejection (§3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyRejection {
    pub at_wall_ns: u64,
    pub reason: String,
    pub attempted_path: String,
    pub attempted_sha256: Option<String>,
}

/// `quota-stop.json` latch (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuotaStop {
    pub schema: String,
    pub generation: u64,
    pub stopped_seq: u64,
    pub at_wall_ns: u64,
    pub cause: String,
    pub bytes: u64,
    pub cap: u64,
}

/// Window file name: `window-<seq:010>.json` (`:010` is a MINIMUM
/// width — wider seqs print fully, §4.2).
pub fn window_name(seq: u64) -> String {
    format!("window-{seq:010}.json")
}

/// Parse a `window-*.json` seq numerically (u64, §4.2).
pub fn parse_window_seq(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("window-")?.strip_suffix(".json")?;
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse::<u64>().ok()
}

/// Rotated stream name (§6.1, `:010` minimum width, numeric order).
pub fn rotated_name(first: u64, last: u64) -> String {
    format!("stream-{first:010}-{last:010}.jsonl")
}

/// True for the rotated pattern `stream-<n>-<m>.jsonl` (§4.1).
pub fn is_rotated_name(name: &str) -> bool {
    let rest = match name
        .strip_prefix("stream-")
        .and_then(|r| r.strip_suffix(".jsonl"))
    {
        Some(r) => r,
        None => return false,
    };
    let (a, b) = match rest.split_once('-') {
        Some(v) => v,
        None => return false,
    };
    !a.is_empty()
        && !b.is_empty()
        && a.bytes().all(|b| b.is_ascii_digit())
        && b.bytes().all(|b| b.is_ascii_digit())
}

/// Reserved out-DIR filenames (§4.1 sink-alias admission — the ONE
/// predicate shared by the pre-start alias check and the post-open
/// fstat re-verification).
pub fn is_reserved_sink_name(name: &str) -> bool {
    matches!(
        name,
        "sequence.json"
            | "policy-status.json"
            | "run-summary.json"
            | "quota-stop.json"
            | "service.lock"
    ) || parse_window_seq(name).is_some()
        || is_rotated_name(name)
}

/// CLOCK_MONOTONIC nanoseconds (close instants, tick edges).
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec.max(0) as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec.max(0) as u64)
}

/// Wall-clock unix nanoseconds (diagnostic stamps). `None` is
/// unrepresentable — callers record explicit nulls, never zero.
pub fn wall_ns() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| {
            d.as_secs()
                .checked_mul(1_000_000_000)?
                .checked_add(u64::from(d.subsec_nanos()))
        })
}

/// Per-op nonce: tmp names never collide across concurrent ops of
/// one run (§4.2).
static OP_NONCE: AtomicU64 = AtomicU64::new(0);

pub fn next_op_nonce() -> u64 {
    OP_NONCE.fetch_add(1, Ordering::Relaxed)
}

/// Mutable-state write: tmp-write, fsync, rename (overwrite
/// intended), fsync(file)+fsync(dir) — §4.2.
pub fn write_state(dir: &Path, name: &str, tag: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp_name = format!(".{name}.tmp.{tag}.{}", next_op_nonce());
    let tmp = dir.join(&tmp_name);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    let final_path = dir.join(name);
    std::fs::rename(&tmp, &final_path)?;
    // fsync(file)+fsync(dir) after the rename.
    let f = File::open(&final_path)?;
    f.sync_all()?;
    sync_dir(dir)?;
    Ok(())
}

/// Best-effort variant for dying runs (§4.3): failure is silent here
/// (the caller already knows its fate); recovery infers the rest.
pub fn write_state_best_effort(dir: &Path, name: &str, tag: &str, bytes: &[u8]) {
    let _ = write_state(dir, name, tag, bytes);
}

/// fsync a directory fd (entry durability, §4.2).
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    let f = File::open(dir)?;
    f.sync_data()?;
    Ok(())
}

/// Owned out-DIR lock (§4.1): `service.lock` + `flock(EX|NB)` held
/// for the whole run. Stale locks are impossible (kernel releases on
/// crash); no lock content is ever evidence.
#[derive(Debug)]
pub struct DirLock {
    _file: File,
    path: std::path::PathBuf,
    /// Pre-take bytes (the refused start restores these, §6.2
    /// byte-identical latch hold).
    prior: Option<Vec<u8>>,
}

/// Bounded pre-take read for [`DirLock::take`] (RANK-1): the
/// §6.2 byte-identical restore needs the full prior bytes, so the
/// read is capped at [`STATE_FILE_CAP`] (a larger lock file is
/// foreign — take refuses WITHOUT mutating, so no restore is
/// owed). Transient read failures keep the historical `.ok()`
/// tolerance (`None`, and the lock open below surfaces hard
/// errors); `O_NONBLOCK` keeps a TOCTOU-swapped FIFO from
/// blocking (the write-open then fails fast with `ENXIO`).
fn read_lock_prior(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Ok(None),
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match f.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > STATE_FILE_CAP {
                    return Err(std::io::Error::other("service.lock exceeds state cap"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(buf))
}

impl DirLock {
    /// Take the lock, writing `{ schema, run_id, started_wall_ns }`
    /// first. A held lock refuses with `AlreadyExists` (caller exits
    /// 2 "out-DIR locked"). The pre-take bytes are retained for
    /// [`DirLock::restore`]. Admission never blocks on lockfile
    /// content (non-regular paths refuse; the prior read is
    /// `O_NONBLOCK` + capped) — startup cannot stall here.
    pub fn take(dir: &Path, run_id: &RunId, started_wall_ns: u64) -> std::io::Result<Self> {
        let path = dir.join("service.lock");
        // Non-blocking admission (RANK-1): never open/read content
        // on a non-regular lock path — a FIFO/socket/dir/device at
        // `service.lock` refuses immediately instead of blocking in
        // open/read while startup has no worker budget to bound it.
        // Lock identity semantics are unchanged (only a regular
        // file — or an absent path — can carry lock identity).
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_file() {
                return Err(std::io::Error::other("service.lock is not a regular file"));
            }
        }
        let prior = read_lock_prior(&path)?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "out-DIR locked",
            ));
        }
        // Truncate + write identity under the held lock.
        use std::os::unix::fs::FileExt as _;
        let body = serde_json::json!({
            "schema": SCHEMA_LOCK,
            "run_id": run_id,
            "started_wall_ns": started_wall_ns,
        });
        let bytes = serde_json::to_vec(&body).map_err(std::io::Error::other)?;
        file.set_len(0)?;
        file.write_all_at(&bytes, 0)?;
        file.sync_all()?;
        Ok(Self {
            _file: file,
            path,
            prior,
        })
    }

    /// Refused start (§6.2 latch hold): restore the pre-take lock
    /// bytes (or remove the file when none existed) and release, so
    /// the refused start leaves no trace. Best-effort, never fails
    /// the exit path.
    pub fn restore(self) {
        let Self {
            _file: file,
            path,
            prior,
        } = self;
        use std::os::unix::fs::FileExt as _;
        match prior {
            Some(bytes) => {
                let _ = file.set_len(0);
                let _ = file.write_all_at(&bytes, 0);
                let _ = file.sync_all();
            }
            None => {
                drop(file);
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Unlink every `.*.tmp.*` in the out-DIR (recovery cleanup, §4.2).
/// Tmps are never evidence; a live run's tmps are protected by the
/// §4.1 lock, so an unlinking run never races one.
pub fn clean_tmps(dir: &Path) -> std::io::Result<u64> {
    let mut removed = 0u64;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(0),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.')
            && name.contains(".tmp.")
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Scan `window-*.json` for the highest parse-verified complete seq
/// `M` (numeric parse, §4.2). `Ok(None)` when no window file exists.
pub fn scan_highest_seq(dir: &Path) -> std::io::Result<Option<u64>> {
    let mut best: Option<u64> = None;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(seq) = parse_window_seq(&name) {
            best = Some(best.map_or(seq, |b| b.max(seq)));
        }
    }
    Ok(best)
}

/// State files are capped at 1 MiB (§6.2 transient bound).
pub const STATE_FILE_CAP: usize = 1 << 20;

pub fn check_state_cap(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > STATE_FILE_CAP {
        return Err("service state file exceeds 1 MiB".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_id() -> RunId {
        RunId {
            pid: 4242,
            starttime: 987_654_321,
            boot_id: "01234567-89ab-cdef".to_string(),
        }
    }

    #[test]
    fn window_naming_minimum_width() {
        assert_eq!(window_name(0), "window-0000000000.json");
        assert_eq!(window_name(41), "window-0000000041.json");
        // Wider seqs print fully, never truncated.
        assert_eq!(window_name(u64::MAX), format!("window-{}.json", u64::MAX));
        assert_eq!(parse_window_seq("window-0000000041.json"), Some(41));
        assert_eq!(parse_window_seq("window-41.json"), Some(41));
        assert_eq!(parse_window_seq("window-.json"), None);
        assert_eq!(parse_window_seq("window-x.json"), None);
        assert_eq!(parse_window_seq("sequence.json"), None);
    }

    #[test]
    fn rotated_naming() {
        assert!(is_rotated_name("stream-0000000001-0000000009.jsonl"));
        assert!(!is_rotated_name("stream.jsonl"));
        assert!(!is_rotated_name("window-0000000001.json"));
        assert!(!is_rotated_name("stream-x-y.jsonl"));
        assert_eq!(rotated_name(1, 9), "stream-0000000001-0000000009.jsonl");
    }

    #[test]
    fn state_round_trips_atomically() {
        let dir = std::env::temp_dir().join(format!("sixb-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tag = run_id().tag();
        assert_eq!(tag, "4242-987654321-01234567");
        let st = SequenceState {
            schema: SCHEMA_SEQ.to_string(),
            generation: 3,
            next_seq: 42,
            updated_wall_ns: 7,
            close_completed_ns: Some(9),
            exhausted: false,
            run_id: run_id(),
            reserved: None,
        };
        let bytes = serde_json::to_vec(&st).unwrap();
        write_state(&dir, "sequence.json", &tag, &bytes).unwrap();
        let back: SequenceState =
            serde_json::from_slice(&std::fs::read(dir.join("sequence.json")).unwrap()).unwrap();
        assert_eq!(back, st);
        // No tmp residue.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Field-position regression (R1 C2): `RunId::current` must
    /// read field 22 (starttime), not field 23 (vsize). Pinned
    /// against the established `pin` parser on self, plus an
    /// anonymous-mapping probe proving vsize-independence (a 16 MiB
    /// anon mmap moves vsize; starttime must not budge).
    #[test]
    fn run_id_starttime_is_field_22_not_vsize() {
        fn post_comm(pid: u32) -> Vec<String> {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            stat.rsplit_once(')')
                .unwrap()
                .1
                .split_whitespace()
                .map(str::to_string)
                .collect()
        }
        let me = std::process::id();
        let expect = crate::pin::starttime_of(me).unwrap();
        assert!(expect > 0, "self has a starttime");
        let got = RunId::current().unwrap();
        assert_eq!(got.pid, me);
        assert_eq!(
            got.starttime, expect,
            "RunId::current must equal the established field-22 parser"
        );
        // Anonymous-mapping probe: reserve 16 MiB (vsize moves by
        // ≥16 MiB; rss untouched — never touched).
        let vsize_before: u64 = post_comm(me)[20].parse().unwrap();
        let len = 16 << 20;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED, "anon probe mmap");
        let vsize_after: u64 = post_comm(me)[20].parse().unwrap();
        assert!(
            vsize_after >= vsize_before + len as u64,
            "probe validity: vsize must move ≥16 MiB ({vsize_before} → {vsize_after})"
        );
        assert_eq!(
            RunId::current().unwrap().starttime,
            expect,
            "starttime must not follow vsize"
        );
        assert_eq!(
            crate::service::witness::snapshot_proc(me as i32)
                .unwrap()
                .starttime,
            expect,
            "witness snapshot_proc must equal the established field-22 parser"
        );
        unsafe {
            libc::munmap(ptr, len);
        }
    }

    #[test]
    fn dir_lock_excludes_second_taker() {
        let dir = std::env::temp_dir().join(format!("sixb-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first = DirLock::take(&dir, &run_id(), 1).unwrap();
        let err = DirLock::take(&dir, &run_id(), 2).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        drop(first);
        // Released on drop (kernel semantics on crash).
        let _ = DirLock::take(&dir, &run_id(), 3).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_lock_refuses_non_regular_path_without_blocking() {
        let dir = std::env::temp_dir().join(format!("sixb-lock-nr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A directory at the lock path refuses (same for a FIFO —
        // covered live by `sixb_fifo_lock_admission_fails_fast`).
        std::fs::create_dir(dir.join("service.lock")).unwrap();
        let err = DirLock::take(&dir, &run_id(), 1).unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(dir.join("service.lock").is_dir(), "no mutation on refusal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_lock_refuses_over_cap_prior_without_mutating() {
        let dir = std::env::temp_dir().join(format!("sixb-lock-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let big = vec![b'x'; STATE_FILE_CAP + 1];
        std::fs::write(dir.join("service.lock"), &big).unwrap();
        let err = DirLock::take(&dir, &run_id(), 1).unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(dir.join("service.lock")).unwrap(),
            big,
            "over-cap refusal mutates nothing (no restore owed)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
