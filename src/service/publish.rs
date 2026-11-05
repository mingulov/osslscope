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
