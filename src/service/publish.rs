//! SPDX-License-Identifier: GPL-3.0-or-later
//! §4.2 publication protocol: one crash-safe no-overwrite rule.
//!
//! Write-once evidence (`window-<seq>.json`): tmp-write, fsync,
//! atomic no-overwrite LINK, unlink(tmp), fsync(dir). A partial
//! final-name file is unconstructable: only complete fsync'd bytes
//! are ever linked. The ONE duplicate rule governs every evidence
//! link (§4.4 and §7.2 alike).

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use crate::service::state::{next_op_nonce, sync_dir, window_name};

/// Persistence-step disposition (§4.2): decided by ACTUAL completed
/// steps, never by assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishStep {
    /// link-ok + dir-fsync-ok.
    Durable,
    /// Same-attempt `EEXIST` + byte-identical + same attempt.
    Converged,
    /// link-ok + dir-fsync-failed: UNCERTAIN (visible but the entry
    /// may not survive a crash). The window is neither durable nor
    /// abandoned yet.
    Uncertain,
    /// link failed (non-EEXIST): NOT PUBLISHED.
    NotPublished,
    /// Differing bytes OR a different attempt: fatal integrity
    /// refusal (exit 1; never a skip).
    IntegrityRefusal,
}

/// Publish complete window bytes under `window-<seq>.json`.
///
/// `attempt` is the linker's `(seq, run_id)` encoded for the
/// same-attempt comparison: the existing envelope's `(seq, run_id)`
/// must equal it for convergence. `commit_dir_fsync` performs the
/// entry-durability step; pass a failing hook in tests to exercise
/// the UNCERTAIN row (the injection TOOL is T7.4's; the outcome is
/// not).
pub fn publish_window(
    dir: &Path,
    seq: u64,
    tag: &str,
    bytes: &[u8],
    attempt: &AttemptKey,
    commit_dir_fsync: &dyn Fn(&Path) -> std::io::Result<()>,
) -> PublishStep {
    let final_name = window_name(seq);
    let tmp_name = format!(".{final_name}.tmp.{tag}.{}", next_op_nonce());
    let tmp = dir.join(&tmp_name);
    let staged = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    })();
    if staged.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return PublishStep::NotPublished;
    }
    let final_path = dir.join(&final_name);
    match std::fs::hard_link(&tmp, &final_path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tmp);
            match commit_dir_fsync(dir) {
                Ok(()) => PublishStep::Durable,
                Err(_) => PublishStep::Uncertain,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // THE ONE duplicate rule: byte-compare + same attempt.
            let step = match std::fs::read(&final_path) {
                Ok(existing) => {
                    if existing == bytes && attempt.matches_bytes(&existing) {
                        PublishStep::Converged
                    } else {
                        PublishStep::IntegrityRefusal
                    }
                }
                Err(_) => PublishStep::IntegrityRefusal,
            };
            let _ = std::fs::remove_file(&tmp);
            step
        }
        Err(_) => {
            let _ = std::fs::remove_file(&tmp);
            PublishStep::NotPublished
        }
    }
}

/// Publish with the real dir-fsync commit step.
pub fn publish_window_durable(
    dir: &Path,
    seq: u64,
    tag: &str,
    bytes: &[u8],
    attempt: &AttemptKey,
) -> PublishStep {
    publish_window(dir, seq, tag, bytes, attempt, &sync_dir)
}

/// 64 KiB streaming buffer (matches the spill buffer — one bound
/// for every publication stream).
pub const PUBLISH_BUF_BYTES: usize = 64 * 1024;

/// Streamed publish judgment (step + failing stage/errno when
/// any + the incremental window SHA-256).
pub type StreamedPublish = (PublishStep, Option<(PublishStage, i32)>, String);

/// Publish a streamed window (R1 finding 2b): `head + "[" +
/// array-tmp bytes + "]" + tail` streams into the window tmp
/// through the bounded buffer with an incremental SHA-256, then
/// follows the §4.2 link protocol EXACTLY (same steps, stages, and
/// ONE duplicate rule — the EEXIST byte-compare streams chunked,
/// never holding both files). `array_tmp` is read-only here (the
/// caller owns its lifecycle).
pub fn publish_window_streaming(
    dir: &Path,
    seq: u64,
    tag: &str,
    head: &[u8],
    tail: &[u8],
    array_tmp: &Path,
    attempt: &AttemptKey,
) -> StreamedPublish {
    use sha2::Digest as _;
    use std::io::{Read as _, Write as _};
    let fail = |stage: PublishStage, e: std::io::Error| (stage, e.raw_os_error().unwrap_or(-1));
    let fail_tmp = |tmp: &Path, stage: PublishStage, e: std::io::Error| {
        let _ = std::fs::remove_file(tmp);
        (
            PublishStep::NotPublished,
            Some(fail(stage, e)),
            String::new(),
        )
    };
    let final_name = window_name(seq);
    let tmp_name = format!(".{final_name}.tmp.{tag}.{}", next_op_nonce());
    let tmp = dir.join(&tmp_name);
    let mut f = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) => return fail_tmp(&tmp, PublishStage::TmpWrite, e),
    };
    let mut h = sha2::Sha256::new();
    // Head + `[` (RAM-held — the envelope without the array).
    if let Err(e) = (|| -> std::io::Result<()> {
        f.write_all(head)?;
        h.update(head);
        f.write_all(b"[")?;
        h.update(b"[");
        Ok(())
    })() {
        return fail_tmp(&tmp, PublishStage::TmpWrite, e);
    }
    // Array body: the array tmp streams in bounded chunks.
    let mut array = match std::fs::File::open(array_tmp) {
        Ok(f) => f,
        Err(e) => return fail_tmp(&tmp, PublishStage::TmpWrite, e),
    };
    let mut buf = vec![0u8; PUBLISH_BUF_BYTES];
    loop {
        let n = match array.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return fail_tmp(&tmp, PublishStage::TmpWrite, e),
        };
        if let Err(e) = f.write_all(&buf[..n]) {
            return fail_tmp(&tmp, PublishStage::TmpWrite, e);
        }
        h.update(&buf[..n]);
    }
    // `]` + tail.
    if let Err(e) = (|| -> std::io::Result<()> {
        f.write_all(b"]")?;
        h.update(b"]");
        f.write_all(tail)?;
        h.update(tail);
        Ok(())
    })() {
        return fail_tmp(&tmp, PublishStage::TmpWrite, e);
    }
    if let Err(e) = f.sync_all() {
        return fail_tmp(&tmp, PublishStage::FileFsync, e);
    }
    drop(f);
    let sha256: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let final_path = dir.join(&final_name);
    match std::fs::hard_link(&tmp, &final_path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tmp);
            match sync_dir(dir) {
                Ok(()) => (PublishStep::Durable, None, sha256),
                Err(e) => (
                    PublishStep::Uncertain,
                    Some(fail(PublishStage::DirFsync, e)),
                    sha256,
                ),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // THE ONE duplicate rule, streamed: chunked
            // byte-compare (never holding both files) + same
            // attempt. The attempt parse still reads the existing
            // file whole (rare EEXIST-only path — the steady path
            // never holds window bytes; twin-audited, R1 finding 2b).
            let step = match files_equal_chunked(&tmp, &final_path) {
                Ok(true) => match std::fs::read(&final_path) {
                    Ok(existing) if attempt.matches_bytes(&existing) => PublishStep::Converged,
                    _ => PublishStep::IntegrityRefusal,
                },
                Ok(false) => PublishStep::IntegrityRefusal,
                Err(read_err) => {
                    let _ = std::fs::remove_file(&tmp);
                    return (
                        PublishStep::IntegrityRefusal,
                        Some(fail(PublishStage::ReadExisting, read_err)),
                        sha256,
                    );
                }
            };
            let _ = std::fs::remove_file(&tmp);
            (step, None, sha256)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            (
                PublishStep::NotPublished,
                Some(fail(PublishStage::Link, e)),
                sha256,
            )
        }
    }
}

/// Chunked file equality (bounded buffer — neither file is held).
fn files_equal_chunked(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::io::Read as _;
    let (mut fa, mut fb) = (std::fs::File::open(a)?, std::fs::File::open(b)?);
    if fa.metadata()?.len() != fb.metadata()?.len() {
        return Ok(false);
    }
    let (mut ba, mut bb) = (vec![0u8; PUBLISH_BUF_BYTES], vec![0u8; PUBLISH_BUF_BYTES]);
    loop {
        let (na, nb) = (fa.read(&mut ba)?, fb.read(&mut bb)?);
        if na != nb || ba[..na] != bb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

/// Publish stage for Control-2 abandonment reasons + the stderr
/// cause line (the step is judged by `PublishStep`; the stage names
/// WHERE it failed — T7.4's naming, the outcomes are frozen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishStage {
    TmpWrite,
    FileFsync,
    Link,
    DirFsync,
    ReadExisting,
}

/// Stage-detailed publish: the frozen `PublishStep` + the failing
/// stage and errno (for the abandonment reason + `close_accounting`
/// stderr line — `ENOSPC` at any stage ⟹ `disk_full`, any other IO
/// error ⟹ `io_error`, T7.4's stage→reason map, reported).
pub fn publish_window_detailed(
    dir: &Path,
    seq: u64,
    tag: &str,
    bytes: &[u8],
    attempt: &AttemptKey,
) -> (PublishStep, Option<(PublishStage, i32)>) {
    use std::io::Write;
    let final_name = window_name(seq);
    let tmp_name = format!(".{final_name}.tmp.{tag}.{}", next_op_nonce());
    let tmp = dir.join(&tmp_name);
    let open = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp);
    let mut f = match open {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return (
                PublishStep::NotPublished,
                Some((PublishStage::TmpWrite, e.raw_os_error().unwrap_or(-1))),
            );
        }
    };
    if let Err(e) = f.write_all(bytes) {
        let _ = std::fs::remove_file(&tmp);
        return (
            PublishStep::NotPublished,
            Some((PublishStage::TmpWrite, e.raw_os_error().unwrap_or(-1))),
        );
    }
    if let Err(e) = f.sync_all() {
        let _ = std::fs::remove_file(&tmp);
        return (
            PublishStep::NotPublished,
            Some((PublishStage::FileFsync, e.raw_os_error().unwrap_or(-1))),
        );
    }
    drop(f);
    let final_path = dir.join(&final_name);
    match std::fs::hard_link(&tmp, &final_path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tmp);
            match sync_dir(dir) {
                Ok(()) => (PublishStep::Durable, None),
                Err(e) => (
                    PublishStep::Uncertain,
                    Some((PublishStage::DirFsync, e.raw_os_error().unwrap_or(-1))),
                ),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let step = match std::fs::read(&final_path) {
                Ok(existing) => {
                    if existing == bytes && attempt.matches_bytes(&existing) {
                        PublishStep::Converged
                    } else {
                        PublishStep::IntegrityRefusal
                    }
                }
                Err(read_err) => {
                    let _ = std::fs::remove_file(&tmp);
                    return (
                        PublishStep::IntegrityRefusal,
                        Some((
                            PublishStage::ReadExisting,
                            read_err.raw_os_error().unwrap_or(-1),
                        )),
                    );
                }
            };
            let _ = std::fs::remove_file(&tmp);
            (step, None)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            (
                PublishStep::NotPublished,
                Some((PublishStage::Link, e.raw_os_error().unwrap_or(-1))),
            )
        }
    }
}

/// The linker's attempt key: `(seq, run_id)` of the envelope being
/// published. Same-attempt convergence requires the existing file's
/// envelope to name the same attempt (a same-run retry converging
/// with a late P1, §7.2) AND byte-identical content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptKey {
    pub seq: u64,
    pub pid: u32,
    pub starttime: u64,
    pub boot_id: String,
}

impl AttemptKey {
    /// Parse the existing envelope's `(seq, run_id)` from its bytes
    /// (tolerant: any parse failure is NOT a match — refusal, never
    /// a skip).
    pub fn matches_bytes(&self, existing: &[u8]) -> bool {
        let v: serde_json::Value = match serde_json::from_slice(existing) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let seq = v.get("seq").and_then(serde_json::Value::as_u64);
        let run = v.get("run_id");
        let pid = run
            .and_then(|r| r.get("pid"))
            .and_then(serde_json::Value::as_u64);
        let starttime = run
            .and_then(|r| r.get("starttime"))
            .and_then(serde_json::Value::as_u64);
        let boot_id = run
            .and_then(|r| r.get("boot_id"))
            .and_then(serde_json::Value::as_str);
        match (seq, pid, starttime, boot_id) {
            (Some(s), Some(p), Some(t), Some(b)) => {
                s == self.seq
                    && p == u64::from(self.pid)
                    && t == self.starttime
                    && b == self.boot_id
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seq: u64) -> AttemptKey {
        AttemptKey {
            seq,
            pid: 7,
            starttime: 8,
            boot_id: "boot".to_string(),
        }
    }

    fn env_bytes(seq: u64, pid: u32) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "service-window-v1",
            "seq": seq,
            "run_id": {"pid": pid, "starttime": 8, "boot_id": "boot"},
        }))
        .unwrap()
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sixb-pub-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn fresh_link_is_durable() {
        let d = dir("fresh");
        let bytes = env_bytes(3, 7);
        let step = publish_window_durable(&d, 3, "t", &bytes, &key(3));
        assert_eq!(step, PublishStep::Durable);
        assert_eq!(
            std::fs::read(d.join("window-0000000003.json")).unwrap(),
            bytes
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn same_attempt_byte_identical_converges() {
        let d = dir("converge");
        let bytes = env_bytes(3, 7);
        assert_eq!(
            publish_window_durable(&d, 3, "t", &bytes, &key(3)),
            PublishStep::Durable
        );
        // Same-run retry: identical bytes + same attempt.
        assert_eq!(
            publish_window_durable(&d, 3, "t", &bytes, &key(3)),
            PublishStep::Converged
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cross_attempt_eexist_is_fatal() {
        let d = dir("cross");
        assert_eq!(
            publish_window_durable(&d, 3, "t", &env_bytes(3, 7), &key(3)),
            PublishStep::Durable
        );
        // Different attempt, same bytes shape: refusal.
        assert_eq!(
            publish_window_durable(&d, 3, "t2", &env_bytes(3, 9), &key(3)),
            PublishStep::IntegrityRefusal
        );
        // Same attempt key but differing bytes: refusal.
        let mut other = env_bytes(3, 7);
        other.extend_from_slice(b" ");
        assert_eq!(
            publish_window_durable(&d, 3, "t", &other, &key(3)),
            PublishStep::IntegrityRefusal
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dir_fsync_failure_is_uncertain() {
        let d = dir("uncertain");
        let bytes = env_bytes(3, 7);
        let fail = |_: &Path| -> std::io::Result<()> {
            Err(std::io::Error::other("injected dirsync loss"))
        };
        assert_eq!(
            publish_window(&d, 3, "t", &bytes, &key(3), &fail),
            PublishStep::Uncertain
        );
        // Visible but unproven: the file exists.
        assert!(d.join("window-0000000003.json").is_file());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Streaming publish is byte-identical to the detailed
    /// publish (same bytes + sha) + follows the ONE duplicate
    /// rule (converge/refuse) — R1 finding 2b.
    #[test]
    fn streaming_matches_detailed_byte_identical() {
        let d = dir("streaming");
        // (head ends before `[`: the helper wraps the array body.)
        let head = br#"{"schema":"service-window-v1","seq":3,"run_id":{"pid":7,"starttime":8,"boot_id":"boot"},"crypto_watch":"#.to_vec();
        let tail = br#","document":{}}"#.to_vec();
        let array = br#"{"k":1},{"k":2}"#;
        let array_tmp = d.join("array.tmp");
        std::fs::write(&array_tmp, array).unwrap();
        let (step, stage, sha) =
            publish_window_streaming(&d, 3, "t", &head, &tail, &array_tmp, &key(3));
        assert_eq!(step, PublishStep::Durable);
        assert_eq!(stage, None);
        let mut expect = head.clone();
        expect.push(b'[');
        expect.extend_from_slice(array);
        expect.push(b']');
        expect.extend_from_slice(&tail);
        let got = std::fs::read(d.join("window-0000000003.json")).unwrap();
        assert_eq!(got, expect);
        assert_eq!(sha, crate::kinds::prov_hash(&expect));
        // Same-attempt retry converges (streamed compare).
        let (step2, _, sha2) =
            publish_window_streaming(&d, 3, "t", &head, &tail, &array_tmp, &key(3));
        assert_eq!(step2, PublishStep::Converged);
        assert_eq!(sha2, sha);
        // Differing bytes refuse.
        let array_tmp2 = d.join("array2.tmp");
        std::fs::write(&array_tmp2, br#"{"k":9}"#).unwrap();
        let (step3, _, _) =
            publish_window_streaming(&d, 3, "t", &head, &tail, &array_tmp2, &key(3));
        assert_eq!(step3, PublishStep::IntegrityRefusal);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_partial_final_name_file() {
        let d = dir("nopartial");
        // Stage into a read-only DIR: link never attempted, no final.
        let ro = d.join("ro");
        std::fs::create_dir(&ro).unwrap();
        let mut perms = std::fs::metadata(&ro).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&ro, perms).unwrap();
        let step = publish_window_durable(&ro, 0, "t", &env_bytes(0, 7), &key(0));
        assert_eq!(step, PublishStep::NotPublished);
        assert!(!ro.join("window-0000000000.json").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
