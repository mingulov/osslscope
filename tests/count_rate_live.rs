//! c6 live count-rate conservation legs (NOT RUN in CI: need caps +
//! /opt/openssl-live + OSSL_RATE_LIVE=1 on the live lane).
//!
//! Drives the shipped binary (`report run -- count_flood ...`) over
//! known-N digest workloads and asserts doc-level conservation:
//! A/A determinism, exact 2x linearity below the knee, hot-key
//! per-key exactness, the loss-knee table, and the independent
//! ledger identity (`count.ledger_delta == 0`, gap-accept 3/14 live
//! proof) on every run. Absolutes are never inferred from loop
//! counts (plan R21 c6): only determinism, scaling factors, and the
//! kernel-side ledger identity are asserted.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const OPT_CRYPTO: &str = "/opt/openssl-live/lib64/libcrypto.so";
const OPT_INC: &str = "/opt/openssl-live/include";
const OPT_LIB: &str = "/opt/openssl-live/lib64";

fn gated() -> Option<()> {
    if std::env::var("OSSL_RATE_LIVE").unwrap_or_default() != "1" {
        eprintln!("rate live leg: set OSSL_RATE_LIVE=1; skipping");
        return None;
    }
    Some(())
}

fn have(cmd: &str, probe: &[&str]) -> bool {
    Command::new(cmd)
        .args(probe)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn prereqs() -> Option<PathBuf> {
    gated()?;
    if !have("gcc", &["--version"]) {
        eprintln!("SKIP rate: no gcc (fixture build unavailable)");
        return None;
    }
    if !Path::new(OPT_CRYPTO).exists() {
        eprintln!("SKIP rate: no {OPT_CRYPTO} (provision the /opt source build)");
        return None;
    }
    if !Path::new("/opt/openssl-live/include/openssl/evp.h").exists() {
        eprintln!("SKIP rate: no /opt openssl headers");
        return None;
    }
    Some(PathBuf::from(env!("CARGO_BIN_EXE_osslscope")))
}

fn stage(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osslscope-ratelive-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn out_dir() -> PathBuf {
    match std::env::var("OSSL_RATE_OUT") {
        Ok(d) => {
            let p = PathBuf::from(d);
            std::fs::create_dir_all(&p).unwrap();
            p
        }
        Err(_) => stage("out"),
    }
}

/// Build count_flood against the /opt source build (rpath-pinned so
/// the observed child resolves the same libcrypto deterministically).
fn build_flood(dir: &Path) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/count_flood.c");
    assert!(src.exists(), "fixture missing: {}", src.display());
    let bin = dir.join("count_flood");
    let st = Command::new("gcc")
        .args(["-O1", "-o"])
        .arg(&bin)
        .arg(&src)
        .arg(format!("-I{OPT_INC}"))
        .arg(format!("-L{OPT_LIB}"))
        .arg("-lcrypto")
        .arg("-lpthread")
        .arg(format!("-Wl,-rpath,{OPT_LIB}"))
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "gcc flood build failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    // Smoke: 1x1 runs and prints its LEDGER line.
    let smoke = Command::new(&bin)
        .args(["1", "1", "0", "sha256"])
        .output()
        .unwrap();
    assert!(smoke.status.success(), "flood smoke failed");
    let text = String::from_utf8_lossy(&smoke.stdout).into_owned();
    assert!(
        text.contains("LEDGER offered=1 "),
        "flood smoke LEDGER line missing: {text:?}"
    );
    bin
}
/// One observed run: `report run` over the flood; returns the parsed
/// doc. Exit 0 or 3 (honest PARTIAL) both acceptable; anything else
/// (incl. wrapper timeout 124) fails loudly.
fn run_leg(bin: &Path, dir: &Path, tag: &str, flood: &Path, args: &[&str]) -> serde_json::Value {
    let doc_path = dir.join(format!("{tag}.json"));
    let mut cmd = vec![
        "report".to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--out".to_string(),
        doc_path.to_string_lossy().into_owned(),
        "--duration".to_string(),
        "100".to_string(),
        "--timeout".to_string(),
        "120".to_string(),
        "run".to_string(),
        "--".to_string(),
        flood.to_string_lossy().into_owned(),
    ];
    for a in args {
        cmd.push(a.to_string());
    }
    let out = Command::new("timeout")
        .arg("400")
        .arg(bin)
        .args(&cmd)
        .output()
        .unwrap();
    let code = out.status.code();
    assert!(
        matches!(code, Some(0) | Some(3)),
        "report run {tag} exit {code:?} (124=wrapper timeout): stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let text = std::fs::read_to_string(&doc_path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn counters(doc: &serde_json::Value) -> HashMap<String, u64> {
    doc["completeness"]["counters"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap_or("").to_string(),
                c["value"].as_u64().unwrap_or(0),
            )
        })
        .collect()
}

/// Sorted per-site calls multiset (identity-free: first/last_ns vary
/// run to run, so A/A equality is exact multiset equality).
fn calls_multiset(doc: &serde_json::Value) -> Vec<u64> {
    let mut v: Vec<u64> = doc["sites"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|s| s["calls"].as_u64().unwrap_or(0))
        .filter(|c| *c > 0)
        .collect();
    v.sort_unstable();
    v
}

fn total_calls(doc: &serde_json::Value) -> u64 {
    calls_multiset(doc).iter().sum()
}

/// Gap-accept 3/14 live proof + lossless legs: every run must show
/// a zero ledger delta with zero drops, zero unattributed, zero
/// shortfall. Absent counters fail (never a silent pass).
fn assert_ledger_clean(doc: &serde_json::Value, tag: &str) {
    let c = counters(doc);
    assert_eq!(c.get("count.ledger_delta"), Some(&0), "{tag}: ledger_delta");
    assert_eq!(
        c.get("count.map_insert_dropped"),
        Some(&0),
        "{tag}: dropfail"
    );
    assert_eq!(c.get("count.unattributed"), Some(&0), "{tag}: unattributed");
    assert_eq!(c.get("count.drain_shortfall"), Some(&0), "{tag}: shortfall");
}

/// A/A determinism: two identical 4x2000 runs observe identical
/// per-site multisets with a clean ledger — lossless repeatability.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_RATE_LIVE=1)"]
fn rate_aa_determinism_exact() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("aa");
    let flood = build_flood(&dir);
    let a = run_leg(&bin, &dir, "aa-a", &flood, &["4", "2000", "0", "sha256"]);
    let b = run_leg(&bin, &dir, "aa-b", &flood, &["4", "2000", "0", "sha256"]);
    assert!(!calls_multiset(&a).is_empty(), "leg A observed no sites");
    assert_eq!(
        calls_multiset(&a),
        calls_multiset(&b),
        "A/A multisets differ"
    );
    assert_eq!(total_calls(&a), total_calls(&b));
    assert_ledger_clean(&a, "aa-a");
    assert_ledger_clean(&b, "aa-b");
    std::fs::copy(dir.join("aa-a.json"), out_dir().join("rate-aa-a.json")).unwrap();
    std::fs::copy(dir.join("aa-b.json"), out_dir().join("rate-aa-b.json")).unwrap();
}
/// Exact 2x linearity below the knee: doubling offered ops doubles
/// every site's observed calls exactly (scaling factor asserted,
/// never absolutes from loop counts).
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_RATE_LIVE=1)"]
fn rate_linearity_exact_below_knee() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("lin");
    let flood = build_flood(&dir);
    let a = run_leg(&bin, &dir, "lin-1x", &flood, &["4", "2000", "0", "sha256"]);
    let b = run_leg(&bin, &dir, "lin-2x", &flood, &["4", "4000", "0", "sha256"]);
    let ma = calls_multiset(&a);
    let mb = calls_multiset(&b);
    assert!(!ma.is_empty(), "1x leg observed no sites");
    assert_eq!(ma.len(), mb.len(), "site count changed across 1x/2x");
    let doubled: Vec<u64> = ma.iter().map(|c| c * 2).collect();
    assert_eq!(mb, doubled, "2x leg is not exactly double per site");
    assert_eq!(total_calls(&b), total_calls(&a) * 2);
    assert_ledger_clean(&a, "lin-1x");
    assert_ledger_clean(&b, "lin-2x");
}

/// Hot-key per-key live: mixed mode drives two hot digests; A/A
/// rerun is exact per site and the ledger is clean.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_RATE_LIVE=1)"]
fn rate_hot_key_live_exact() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("hot");
    let flood = build_flood(&dir);
    let a = run_leg(&bin, &dir, "hot-a", &flood, &["8", "1000", "0", "mixed"]);
    let b = run_leg(&bin, &dir, "hot-b", &flood, &["8", "1000", "0", "mixed"]);
    let ma = calls_multiset(&a);
    assert!(
        ma.len() >= 2,
        "mixed leg must show 2+ hot sites, saw {ma:?}"
    );
    assert_eq!(ma, calls_multiset(&b), "hot-key A/A multisets differ");
    assert_ledger_clean(&a, "hot-a");
    assert_ledger_clean(&b, "hot-b");
    let top2: u64 = ma.iter().rev().take(2).sum();
    let record = serde_json::json!({
        "sites": ma.len(),
        "top2_calls": top2,
        "total_calls": total_calls(&a),
    });
    std::fs::write(
        out_dir().join("rate-hot.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

/// Loss-knee characterization: sweep 1/2/4/8 threads at fixed ops;
/// every point below the knee is exactly conserved; the knee
/// position (first lossy point) is recorded, never asserted away.
/// A knee at 1 thread fails (single-threaded loss is a defect).
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_RATE_LIVE=1)"]
fn rate_knee_characterization_recorded() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("knee");
    let flood = build_flood(&dir);
    let mut points = Vec::new();
    let mut knee_at: Option<u32> = None;
    for t in [1u32, 2, 4, 8] {
        let tag = format!("knee-{t}t");
        let ops = "3000";
        let doc = run_leg(
            &bin,
            &dir,
            &tag,
            &flood,
            &[&t.to_string(), ops, "0", "sha256"],
        );
        let c = counters(&doc);
        let clean = c.get("count.ledger_delta") == Some(&0)
            && c.get("count.map_insert_dropped") == Some(&0)
            && c.get("count.unattributed") == Some(&0)
            && c.get("count.drain_shortfall") == Some(&0);
        if !clean && knee_at.is_none() {
            knee_at = Some(t);
        }
        if knee_at.is_none() {
            assert!(clean, "below-knee point {t}t must be exactly conserved");
            assert!(!calls_multiset(&doc).is_empty(), "point {t}t saw no sites");
        }
        points.push(serde_json::json!({
            "threads": t,
            "offered": t as u64 * 3000,
            "observed_total": total_calls(&doc),
            "ledger_admitted": c.get("count.ledger_admitted").copied().unwrap_or(0),
            "ledger_delta": c.get("count.ledger_delta").copied(),
            "dropfail": c.get("count.map_insert_dropped").copied().unwrap_or(0),
            "unattributed": c.get("count.unattributed").copied().unwrap_or(0),
            "shortfall": c.get("count.drain_shortfall").copied().unwrap_or(0),
            "status": doc["completeness"]["status"],
        }));
    }
    assert_ne!(
        knee_at,
        Some(1),
        "knee at 1 thread: single-threaded loss is a defect"
    );
    let record = serde_json::json!({"knee_at_threads": knee_at, "points": points});
    std::fs::write(
        out_dir().join("rate-knee.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}
