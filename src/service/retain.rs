//! SPDX-License-Identifier: GPL-3.0-or-later
//! §6 rotation and retention: measured/managed sets, oldest-first
//! deletion, the latest-window protection, quota failure (latch +
//! L4-extended unlatched-stop defense).

use std::path::{Path, PathBuf};

use crate::service::envelope::{OpOutcome, QuotaCause, QuotaExceeded, RunSummary};
use crate::service::state::{
    QuotaStop, RunId, SCHEMA_QUOTA_STOP, is_rotated_name, parse_window_seq, sync_dir, wall_ns,
    write_state,
};

/// Managed-set scan: window files + resident rotated streams.
#[derive(Debug, Default)]
pub struct ManagedScan {
    /// `(seq, bytes, path)` sorted by numeric seq ascending.
    pub windows: Vec<(u64, u64, PathBuf)>,
    /// `(first, last, bytes, path)` sorted by `last_seq` ascending.
    pub rotated: Vec<(u64, u64, u64, PathBuf)>,
    pub managed_bytes: u64,
}

pub fn scan_managed(dir: &Path) -> ManagedScan {
    let mut scan = ManagedScan::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return scan,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if let Some(seq) = parse_window_seq(&name) {
            scan.windows.push((seq, bytes, path));
            scan.managed_bytes += bytes;
        } else if is_rotated_name(&name) {
            if let Some((first, last)) = rotated_span(&name) {
                scan.rotated.push((first, last, bytes, path));
                scan.managed_bytes += bytes;
            }
        }
    }
    scan.windows.sort_by_key(|w| w.0);
    scan.rotated.sort_by_key(|r| r.1);
    scan
}

fn rotated_span(name: &str) -> Option<(u64, u64)> {
    let rest = name.strip_prefix("stream-")?.strip_suffix(".jsonl")?;
    let (a, b) = rest.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// Retention outcome (§6.2): deletions oldest-first, latest window
/// protected, failures retried next boundary (never fatal, never
/// silent).
#[derive(Debug)]
pub struct RetentionOut {
    pub deleted_files: u64,
    pub deleted_bytes: u64,
    /// Per-file deletion failures (stderr diagnostics + retry).
    pub delete_errors: Vec<String>,
    pub window_count: u64,
    pub managed_bytes: u64,
    /// Set when quota is still exceeded after all deletable
    /// candidates are gone (cause decides continue vs stop).
    pub quota_exceeded: Option<QuotaExceeded>,
}

pub fn enforce_retention(dir: &Path, retain_windows: u64, retain_bytes: u64) -> RetentionOut {
    let mut scan = scan_managed(dir);
    let mut out = RetentionOut {
        deleted_files: 0,
        deleted_bytes: 0,
        delete_errors: Vec::new(),
        window_count: scan.windows.len() as u64,
        managed_bytes: scan.managed_bytes,
        quota_exceeded: None,
    };
    // Latest complete window is NEVER removed (protection is bounded
    // by §5.1 caps + the spill note, §6.2).
    let latest: Option<u64> = scan.windows.last().map(|w| w.0);
    loop {
        let over_count = out.window_count > retain_windows;
        let over_bytes = out.managed_bytes > retain_bytes;
        if !over_count && !over_bytes {
            break;
        }
        // Oldest by seq (windows) / last_seq (rotated); on a
        // window-seq == stream-last_seq tie the rotated stream goes
        // first (windows are primary evidence).
        let next = oldest_deletable(&scan, latest);
        let Some((is_window, bytes, path)) = next else {
            break;
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {
                out.deleted_files += 1;
                out.deleted_bytes += bytes;
                out.managed_bytes -= bytes;
                if is_window {
                    out.window_count -= 1;
                    scan.windows.retain(|w| w.2 != path);
                } else {
                    scan.rotated.retain(|r| r.3 != path);
                }
            }
            Err(e) => {
                out.delete_errors
                    .push(format!("retention delete {} failed: {e}", path.display()));
                // Stop deleting THIS boundary on failure (retry next
                // boundary); the cause decision below still runs.
                break;
            }
        }
    }
    let _ = sync_dir(dir);
    // Cause decision (evidence never force-deleted either way).
    if out.window_count > retain_windows || out.managed_bytes > retain_bytes {
        if oldest_deletable(&scan, latest).is_none() {
            // Only protected evidence remains: BOUNDED excess. (A
            // count-only excess is unreachable here: the latest
            // window alone never exceeds a ≥1 count cap, so a
            // protected remainder is always bytes-driven.)
            out.quota_exceeded = Some(QuotaExceeded {
                bytes: out.managed_bytes,
                cap: retain_bytes,
                cause: QuotaCause::ProtectedEvidence,
            });
        } else {
            // Deletable candidates remain but deletions fail:
            // UNBOUNDED condition → the run stops growing (§6.2).
            out.quota_exceeded = Some(QuotaExceeded {
                bytes: out.managed_bytes,
                cap: retain_bytes,
                cause: QuotaCause::DeletionFailure,
            });
        }
    }
    out
}

/// Oldest deletable candidate, or `None` when only protected
/// evidence remains (latest window + never-remove set).
fn oldest_deletable(scan: &ManagedScan, latest: Option<u64>) -> Option<(bool, u64, PathBuf)> {
    let oldest_window = scan
        .windows
        .iter()
        .find(|w| Some(w.0) != latest)
        .map(|w| (w.0, w.1, w.2.clone()));
    let oldest_rotated = scan.rotated.first().map(|r| (r.1, r.2, r.3.clone()));
    match (oldest_window, oldest_rotated) {
        (Some((ws, wb, wp)), Some((rl, rb, rp))) => {
            if rl <= ws {
                Some((false, rb, rp))
            } else {
                Some((true, wb, wp))
            }
        }
        (Some((_, wb, wp)), None) => Some((true, wb, wp)),
        (None, Some((_, rb, rp))) => Some((false, rb, rp)),
        (None, None) => None,
    }
}

/// Rotation trigger (§6.1): size ≥ `--rotate-bytes` OR age ≥
/// `--rotate-interval`, whichever hits first. Zero-record files are
/// never rotated (the caller checks the record count and restarts
/// the age clock instead).
pub fn rotation_due(
    size: u64,
    age_secs: u64,
    rotate_bytes: u64,
    rotate_interval_secs: u64,
) -> bool {
    size >= rotate_bytes || age_secs >= rotate_interval_secs
}

/// Rotation rename (§6.1): no-overwrite link+unlink under the §4.1
/// lock. A held rotated name is fatal (exit 1), never a skip.
pub fn rotate_file(active: &Path, rotated: &Path) -> Result<(), String> {
    match std::fs::hard_link(active, rotated) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!("rotated stream name held: {}", rotated.display()));
        }
        Err(e) => return Err(format!("rotation link failed: {e}")),
    }
    std::fs::remove_file(active).map_err(|e| format!("rotation unlink failed: {e}"))?;
    if let Some(dir) = rotated.parent() {
        let _ = sync_dir(dir);
    }
    Ok(())
}

/// Write the quota-stop latch (§6.2): tmp+rename+fsync+dirsync like
/// §4.2 state. Returns the latch bytes for the `quota_latch_write`
/// op accounting (the caller records `done` vs `failed`).
pub fn write_latch(
    dir: &Path,
    tag: &str,
    generation: u64,
    stopped_seq: u64,
    bytes: u64,
    cap: u64,
) -> std::io::Result<()> {
    let latch = QuotaStop {
        schema: SCHEMA_QUOTA_STOP.to_string(),
        generation,
        stopped_seq,
        at_wall_ns: wall_ns().unwrap_or(0),
        cause: "deletion_failure".to_string(),
        bytes,
        cap,
    };
    let body = serde_json::to_vec(&latch).map_err(std::io::Error::other)?;
    write_state(dir, "quota-stop.json", tag, &body)
}

pub fn read_latch(dir: &Path) -> Option<QuotaStop> {
    let bytes = std::fs::read(dir.join("quota-stop.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn clear_latch(dir: &Path) -> std::io::Result<()> {
    std::fs::remove_file(dir.join("quota-stop.json"))?;
    sync_dir(dir)
}

/// Startup quota re-evaluation (latch path, §6.2): delete-eligible
/// candidates under the CURRENT retain caps. Returns `true` when
/// quota is STILL exceeded with no deletable candidate (⟹ exit 4,
/// zero windows, zero bytes).
/// Non-deleting quota evaluation (§6.2 latch path): `(over_quota,
/// deletable_exists)` from live disk truth WITHOUT deleting —
/// the latch-hold MUST exits 4 with a byte-identical DIR, so the
/// pre-start evaluation cannot run `enforce_retention` (which
/// deletes). Deletability follows the same oldest-first rule
/// (latest window protected, tie rotated-first).
/// Unlink possibility probe (no deletion attempted): the DIR must
/// be writable + searchable or no candidate is deletable — a
/// candidate you cannot unlink is not a deletable candidate (a
/// read-only out-DIR refuses with 4 instead of starting into a
/// futile run). TOCTOU-safe: a permissions change between this
/// probe and the delete only reroutes to the mid-run quota-stop,
/// the honest fallback.
pub fn dir_deletion_possible(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = dir.as_os_str().as_bytes();
    let Ok(c) = std::ffi::CString::new(bytes) else {
        return false;
    };
    // SAFETY: `access` only reads metadata.
    unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

pub fn quota_state(dir: &Path, retain_windows: u64, retain_bytes: u64) -> (bool, bool) {
    let scan = scan_managed(dir);
    let over = scan.windows.len() as u64 > retain_windows || scan.managed_bytes > retain_bytes;
    if !over {
        return (false, false);
    }
    let latest = scan.windows.last().map(|w| w.0);
    let candidate = oldest_deletable(&scan, latest).is_some();
    (true, candidate && dir_deletion_possible(dir))
}

pub fn quota_blocked(dir: &Path, retain_windows: u64, retain_bytes: u64) -> bool {
    let out = enforce_retention(dir, retain_windows, retain_bytes);
    if out.window_count <= retain_windows && out.managed_bytes <= retain_bytes {
        return false;
    }
    let scan = scan_managed(dir);
    let latest = scan.windows.last().map(|w| w.0);
    oldest_deletable(&scan, latest).is_none() || !dir_deletion_possible(dir)
}

/// L4-extended unlatched-stop defense (§6.2): no latch file + quota
/// still exceeded with no deletable candidate + EITHER (a) the
/// identity-verified previous summary records
/// `quota_exceeded.cause == deletion_failure` with a NON-DONE
/// `quota_latch_write` op (`failed` per the D-record, plus
/// `expired`/`cancelled`/`lost`/`worker_unavailable` per L4 — ANY
/// non-done word; the latch op runs last at stop time so the
/// 256-entry cap never drops it); OR (b) the previous summary is
/// absent, corrupt, or identity-unverifiable. Refusal: exit 4 BEFORE
/// the first reserve (zero windows, zero bytes, NO summary write —
/// the previous summary stands for the next starter).
pub fn unlatched_defense_blocks(
    prev_summary: Option<&RunSummary>,
    expected_run: &RunId,
    expected_generation: u64,
    quota_still_exceeded_no_deletable: bool,
) -> bool {
    if !quota_still_exceeded_no_deletable {
        return false;
    }
    match prev_summary {
        Some(s) if s.generation == expected_generation && s.run_id == *expected_run => {
            let deletion = s
                .quota_exceeded
                .as_ref()
                .is_some_and(|q| q.cause == QuotaCause::DeletionFailure);
            if !deletion {
                // Verified summary naming only protected_evidence
                // (or nothing): bounded excess restarts keep their
                // availability.
                return false;
            }
            // Clause (a): latch op present with ANY non-done word.
            // Absent latch op with a deletion_failure record means
            // the stop predates/omitted the op — genuinely ambiguous
            // ⟹ fail closed (clause (b) spirit).
            match s
                .close_accounting
                .iter()
                .find(|op| op.op == "quota_latch_write")
            {
                Some(op) => op.outcome != OpOutcome::Done,
                None => true,
            }
        }
        // Clause (b): absent/corrupt/unverifiable ⟹ fail closed.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::envelope::CloseOp;
    use crate::service::state::window_name;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sixb-ret-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn run_id() -> RunId {
        RunId {
            pid: 1,
            starttime: 101,
            boot_id: "boot".to_string(),
        }
    }

    fn write_window(dir: &Path, seq: u64, size: usize) {
        std::fs::write(dir.join(window_name(seq)), vec![b'w'; size]).unwrap();
    }

    #[test]
    fn retention_deletes_oldest_first_protects_latest() {
        let d = dir("oldest");
        for seq in 0..5 {
            write_window(&d, seq, 100);
        }
        let out = enforce_retention(&d, 2, u64::MAX);
        assert_eq!(out.deleted_files, 3);
        assert_eq!(out.window_count, 2);
        assert!(out.quota_exceeded.is_none());
        // Oldest gone, latest two stay.
        assert!(!d.join(window_name(0)).exists());
        assert!(!d.join(window_name(2)).exists());
        assert!(d.join(window_name(3)).exists());
        assert!(d.join(window_name(4)).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn retention_tie_deletes_rotated_first() {
        let d = dir("tie");
        write_window(&d, 5, 100);
        std::fs::write(
            d.join("stream-0000000001-0000000005.jsonl"),
            vec![b's'; 100],
        )
        .unwrap();
        // Over bytes: window-seq 5 == stream last_seq 5 → stream first.
        let out = enforce_retention(&d, u64::MAX, 150);
        assert_eq!(out.deleted_files, 1);
        assert!(!d.join("stream-0000000001-0000000005.jsonl").exists());
        assert!(d.join(window_name(5)).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn protected_evidence_continues_with_record() {
        let d = dir("protected");
        // One window over the byte cap: only protected remains.
        write_window(&d, 0, 200);
        let out = enforce_retention(&d, u64::MAX, 100);
        assert_eq!(out.deleted_files, 0);
        let q = out.quota_exceeded.unwrap();
        assert_eq!(q.cause, QuotaCause::ProtectedEvidence);
        assert!(d.join(window_name(0)).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn latch_round_trip() {
        let d = dir("latch");
        write_latch(&d, "t", 2, 9, 500, 100).unwrap();
        let latch = read_latch(&d).unwrap();
        assert_eq!(latch.stopped_seq, 9);
        assert_eq!(latch.cause, "deletion_failure");
        clear_latch(&d).unwrap();
        assert!(read_latch(&d).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L4 legs: ANY non-done latch word blocks; `done` (operator
    /// intervention) and verified-clean summaries start normally.
    #[test]
    fn l4_every_latch_word_leg() {
        let expected = run_id();
        for outcome in [
            OpOutcome::Failed,
            OpOutcome::Expired,
            OpOutcome::Cancelled,
            OpOutcome::Lost,
            OpOutcome::WorkerUnavailable,
        ] {
            let mut s = RunSummary::blank(expected.clone(), 0, 0);
            s.quota_exceeded = Some(QuotaExceeded {
                bytes: 500,
                cap: 100,
                cause: QuotaCause::DeletionFailure,
            });
            s.close_accounting.push(CloseOp {
                op: "quota_latch_write".to_string(),
                outcome,
            });
            assert!(
                unlatched_defense_blocks(Some(&s), &expected, 0, true),
                "latch word {outcome:?} must block"
            );
        }
        // Done latch op + hand-deleted latch = operator intervention.
        let mut done = RunSummary::blank(expected.clone(), 0, 0);
        done.quota_exceeded = Some(QuotaExceeded {
            bytes: 500,
            cap: 100,
            cause: QuotaCause::DeletionFailure,
        });
        done.close_accounting.push(CloseOp {
            op: "quota_latch_write".to_string(),
            outcome: OpOutcome::Done,
        });
        assert!(!unlatched_defense_blocks(Some(&done), &expected, 0, true));
        // Verified protected-only summary starts normally.
        let mut prot = RunSummary::blank(expected.clone(), 0, 0);
        prot.quota_exceeded = Some(QuotaExceeded {
            bytes: 500,
            cap: 100,
            cause: QuotaCause::ProtectedEvidence,
        });
        assert!(!unlatched_defense_blocks(Some(&prot), &expected, 0, true));
        // Clause (b): absent/unverifiable fails closed.
        assert!(unlatched_defense_blocks(None, &expected, 0, true));
        let alien = RunSummary::blank(
            RunId {
                pid: 2,
                starttime: 102,
                boot_id: "boot".to_string(),
            },
            0,
            0,
        );
        assert!(unlatched_defense_blocks(Some(&alien), &expected, 0, true));
        // No quota pressure: never blocks.
        assert!(!unlatched_defense_blocks(None, &expected, 0, false));
    }

    /// Permission-aware deletability: an over-quota DIR whose
    /// candidate cannot be unlinked (read-only DIR) reports
    /// NOT-deletable, so the latch gate refuses with 4 instead of
    /// starting into a futile run.
    #[test]
    fn quota_state_readonly_dir_is_not_deletable() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = dir("ro-deletable");
        std::fs::write(d.join(window_name(0)), b"w0").unwrap();
        std::fs::write(d.join(window_name(1)), b"w1").unwrap();
        assert_eq!(quota_state(&d, 1, u64::MAX), (true, true));
        let mut perms = std::fs::metadata(&d).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&d, perms).unwrap();
        assert_eq!(quota_state(&d, 1, u64::MAX), (true, false));
        assert!(!dir_deletion_possible(&d));
        let mut perms = std::fs::metadata(&d).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&d, perms).unwrap();
        assert_eq!(quota_state(&d, 1, u64::MAX), (true, true));
        let _ = std::fs::remove_dir_all(&d);
    }
}
