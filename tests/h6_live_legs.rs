//! H6 live legs: file-provider quiet + affirmative absence, wired
//! end to end (NOT RUN in C1: needs a privileged lane + staged
//! harvest BPF object via OSSL_H6_LIVE=1, OSSL_H6_OBJECT=<.o>, OSSL_H6_PROV=<provider .so>).
//!
//! Birth honesty: `observed_from_birth: true` with a
//! spawned-then-attached child has a ~1s blind window; the
//! vehicles here are quiescent sleepers whose preloaded
//! provider is never called, so no query/load/trigger is
//! possible in the window (documented quiescence rationale,
//! not true held-stopped birth).
//!
//! `OSSL_H6_EXPECT=h6` (default) asserts H6 verdicts;
//! `OSSL_H6_EXPECT=base` asserts pre-H6 verdicts (same
//! fixtures, old tree — the flip table).

use std::path::{Path, PathBuf};

fn gated() -> Option<(PathBuf, PathBuf, bool)> {
    if std::env::var("OSSL_H6_LIVE").unwrap_or_default() != "1" {
        eprintln!("h6 live legs: set OSSL_H6_LIVE=1; skipping");
        return None;
    }
    let object: PathBuf = std::env::var("OSSL_H6_OBJECT")
        .expect("OSSL_H6_OBJECT=<harvest BPF .o>")
        .into();
    let prov: PathBuf = std::env::var("OSSL_H6_PROV")
        .expect("OSSL_H6_PROV=<provider .so>")
        .into();
    let expect_h6 = std::env::var("OSSL_H6_EXPECT").unwrap_or_default() != "base";
    Some((object, prov, expect_h6))
}

/// Stage prov.so (+ hardlink alias.so) on a scratch tmpfs-local dir.
/// Returns (prov_path, alias_path). Same-file alias, distinct paths.
fn stage_alias(origin: &PathBuf, tag: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("osslscope-h6live-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prov = dir.join("prov.so");
    std::fs::copy(origin, &prov).unwrap();
    let alias = dir.join("alias.so");
    std::fs::hard_link(&prov, &alias).unwrap();
    (prov, alias)
}

fn spawn_preloaded(preload: &Path) -> std::process::Child {
    std::process::Command::new("sleep")
        .arg("60")
        .env("LD_PRELOAD", preload)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn preloaded sleeper")
}

fn run_harvest(
    object: &Path,
    provider: &Path,
    pid: u32,
    legacy: bool,
    birth: bool,
) -> serde_json::Value {
    let cfg = osslscope::discovery::harvest::Config {
        object_bytes: None,
        pid,
        provider: provider.to_path_buf(),
        object: object.to_path_buf(),
        settle: std::time::Duration::from_millis(500),
        timeout: std::time::Duration::from_secs(10),
        cmdline_marker: None,
        builtin: false,
        legacy,
        table: None,
        force_offset: None,
        observed_from_birth: birth,
    };
    osslscope::discovery::harvest::run(&cfg).expect("harvest run")
}

/// L4: mid-run unlink (expected identity unstatable; the
/// target keeps mapping it, probes stay on the held fd) +
/// birth + NO hook → PARTIAL on both trees (H6:
/// absent-unproven via the hook gate; base: present-quiet).
/// Pins that absence never completes hookless, even at birth.
///
/// (A mid-run rename-over instead fails fast in `inspect`
/// — the kernel flags the old mapping `(deleted)`, the
/// entry match misses, and the one-shot wrapper bails on
/// the failed attach. Both trees, same behavior.)
#[test]
#[ignore = "live lane only (see module docs)"]
fn h6_l4_absent_birth_no_hook_is_partial() {
    let Some((object, origin, _)) = gated() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("osslscope-h6live-l4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prov = dir.join("prov.so");
    std::fs::copy(&origin, &prov).unwrap();
    let mut child = spawn_preloaded(&prov);
    let pid = child.id();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let prov_c = prov.clone();
    let object_c = object.clone();
    let doc = std::thread::scope(|s| {
        let h = s.spawn(move || run_harvest(&object_c, &prov_c, pid, false, true));
        // Mid-run UNLINK of prov.so (V2-65: chmod-000 is a
        // root-noop — root stats through 0o000): the expected
        // identity goes unstatable for everyone incl. root;
        // the mapping + held-fd probes continue unaffected.
        std::thread::sleep(std::time::Duration::from_secs(4));
        std::fs::remove_file(&prov).unwrap();
        h.join().unwrap()
    });
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(doc["status"], "PARTIAL", "absent birth hookless: {doc}");
    assert_eq!(doc["reason"], "no-query-trigger", "frozen reuse: {doc}");
}

/// L5: L4 + legacy hook armed and quiet → H6 COMPLETE-EMPTY
/// (affirmative absence); base PARTIAL (present-quiet). The
/// (c) flip. The preloaded provider pulls system libcrypto,
/// so tripwires plan; nothing loads anything (no hits).
#[test]
#[ignore = "live lane only (see module docs)"]
fn h6_l5_absent_birth_quiet_hook_completes() {
    let Some((object, origin, expect_h6)) = gated() else {
        return;
    };
    let dir = std::env::temp_dir().join(format!("osslscope-h6live-l5-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prov = dir.join("prov.so");
    std::fs::copy(&origin, &prov).unwrap();
    let mut child = spawn_preloaded(&prov);
    let pid = child.id();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let prov_c = prov.clone();
    let object_c = object.clone();
    let doc = std::thread::scope(|s| {
        let h = s.spawn(move || run_harvest(&object_c, &prov_c, pid, true, true));
        // Mid-run UNLINK of prov.so (V2-65, see L4).
        std::thread::sleep(std::time::Duration::from_secs(4));
        std::fs::remove_file(&prov).unwrap();
        h.join().unwrap()
    });
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    if expect_h6 {
        assert!(
            doc.get("status").is_none(),
            "affirmative absence completes: {doc}"
        );
    } else {
        assert_eq!(doc["status"], "PARTIAL", "base stays partial: {doc}");
    }
}

/// L6b: mapped ORIG + silent + birth (no replace, no legacy) →
/// H6 COMPLETE-EMPTY (proven quiet); base PARTIAL
/// (no-query-trigger has no birth flip). The (b) flip.
#[test]
#[ignore = "live lane only (see module docs)"]
fn h6_l6b_mapped_birth_silent_completes() {
    let Some((object, origin, expect_h6)) = gated() else {
        return;
    };
    let (prov, _alias) = stage_alias(&origin, "l6b");
    let mut child = spawn_preloaded(&prov);
    let pid = child.id();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let doc = run_harvest(&object, &prov, pid, false, true);
    let _ = child.kill();
    let _ = child.wait();
    if expect_h6 {
        assert!(
            doc.get("status").is_none(),
            "mapped birth silent completes: {doc}"
        );
    } else {
        assert_eq!(doc["status"], "PARTIAL", "base stays partial: {doc}");
        assert_eq!(doc["reason"], "no-query-trigger", "base reason: {doc}");
    }
}
