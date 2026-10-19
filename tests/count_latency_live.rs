//! c8 live latency/scan-tail/drain/memory legs (NOT RUN in CI: need
//! caps + /opt/openssl-live + OSSL_LAT_LIVE=1 on the live lane).
//!
//! Scores the <=4us median budget on the MEASURED BPF callback
//! distribution (fast + paced regimes a la R21 finding 10),
//! records scan-tail (p99 + top bucket), drain, memory, cold cost,
//! and the matched wall-clock ratio (scored only at >=100k ops/s
//! sustained, else NOT_SCORED).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const OPT_CRYPTO: &str = "/opt/openssl-live/lib64/libcrypto.so";
const OPT_INC: &str = "/opt/openssl-live/include";
const OPT_LIB: &str = "/opt/openssl-live/lib64";

fn gated() -> Option<()> {
    if std::env::var("OSSL_LAT_LIVE").unwrap_or_default() != "1" {
        eprintln!("latency live leg: set OSSL_LAT_LIVE=1; skipping");
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
        eprintln!("SKIP latency: no gcc");
        return None;
    }
    if !Path::new(OPT_CRYPTO).exists() {
        eprintln!("SKIP latency: no {OPT_CRYPTO}");
        return None;
    }
    if !Path::new("/opt/openssl-live/include/openssl/evp.h").exists() {
        eprintln!("SKIP latency: no /opt openssl headers");
        return None;
    }
    Some(PathBuf::from(env!("CARGO_BIN_EXE_osslscope")))
}

fn stage(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osslscope-latlive-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn out_dir() -> PathBuf {
    match std::env::var("OSSL_LAT_OUT") {
        Ok(d) => {
            let p = PathBuf::from(d);
            std::fs::create_dir_all(&p).unwrap();
            p
        }
        Err(_) => stage("out"),
    }
}

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
    bin
}

/// The target libcrypto is named explicitly (`--provider` +
/// `--builtin`): pre-exec auto-discovery predicts "no NEEDED
/// libcrypto" for the Fedora-guest gcc flood binary and refuses
/// the exe as an unrecognized library (cycle-1 exit 4; T3-49a88a6
/// pinned shape + fix). Explicit provider is the
/// product-sanctioned path (`docs/usage.md`); leg assertions
/// unaffected.
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
        "--provider".to_string(),
        format!("{OPT_LIB}/libcrypto.so.3"),
        "--builtin".to_string(),
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
        "report run {tag} exit {code:?}: stdout={:?} stderr={:?}",
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

fn buckets(c: &HashMap<String, u64>) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (k, slot) in out.iter_mut().enumerate() {
        let name = format!("count.lat_bucket_{k:02}");
        *slot = c.get(&name).copied().unwrap_or(0);
    }
    out
}

/// Score one regime: samples exist, buckets sum to samples, median
/// meets the <=4us budget; record median/p99/tail/status.
fn score_regime(doc: &serde_json::Value, tag: &str, out: &Path) {
    let c = counters(doc);
    let samples = c.get("count.lat_samples").copied().unwrap_or(0);
    assert!(samples > 0, "{tag}: no latency samples measured");
    let b = buckets(&c);
    assert_eq!(
        b.iter().sum::<u64>(),
        samples,
        "{tag}: buckets must sum to samples"
    );
    let median = c.get("count.lat_median_ns").copied().unwrap_or(u64::MAX);
    let p99 = c.get("count.lat_p99_ns").copied().unwrap_or(u64::MAX);
    assert!(
        median <= 4000,
        "{tag}: median callback latency {median}ns exceeds the 4000ns budget"
    );
    let top = b.iter().rposition(|n| *n > 0).unwrap_or(0);
    let record = serde_json::json!({
        "regime": tag,
        "samples": samples,
        "median_ns": median,
        "p99_ns": p99,
        "top_bucket": top,
        "top_bucket_count": b[top],
        "buckets": b.to_vec(),
        "status": doc["completeness"]["status"],
    });
    std::fs::write(
        out.join(format!("lat-{tag}.json")),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
    assert_eq!(c.get("count.ledger_delta"), Some(&0), "{tag}: ledger");
}

/// Fast regime: 4x25000 ops at the minimal 100us pace that
/// attaches (diag-proven: unpaced yields zero samples via
/// exec_gap, T3 finding 3; 100us keeps the high-rate intent).
/// Scores the budget on the measured distribution (R21 recorded
/// amortized estimates here).
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_LAT_LIVE=1)"]
fn latency_fast_distribution_measured() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("fast");
    let flood = build_flood(&dir);
    let doc = run_leg(
        &bin,
        &dir,
        "lat-fast",
        &flood,
        &["4", "25000", "100", "sha256"],
    );
    score_regime(&doc, "fast", &out_dir());
    std::fs::copy(
        dir.join("lat-fast.json"),
        out_dir().join("lat-fast-doc.json"),
    )
    .unwrap();
}

/// Paced regime: 1x60 ops at 500ms pace (~30s workload, full walk
/// per op). Same scoring as fast.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_LAT_LIVE=1)"]
fn latency_paced_distribution_measured() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("paced");
    let flood = build_flood(&dir);
    let doc = run_leg(
        &bin,
        &dir,
        "lat-paced",
        &flood,
        &["1", "60", "500000", "sha256"],
    );
    score_regime(&doc, "paced", &out_dir());
    std::fs::copy(
        dir.join("lat-paced.json"),
        out_dir().join("lat-paced-doc.json"),
    )
    .unwrap();
}
/// Observed workload-only wall: the child times itself with
/// `date +%s%N` into a file (attach time excluded from the
/// ratio). Returns (doc, workload_ns).
///
/// The target libcrypto is named explicitly (`--provider` +
/// `--builtin`): the observed `sh -c ...` resolves to
/// /usr/sbin/sh, which auto-discovery refuses with exit 4
/// (cycle-1 `not OpenSSL` shape; T4-670a5f4 pinned fix).
/// Explicit provider is the product-sanctioned path
/// (`docs/usage.md`); leg assertions unaffected.
fn run_wall(
    bin: &Path,
    dir: &Path,
    tag: &str,
    flood: &Path,
    args: &[&str],
) -> (serde_json::Value, u64) {
    let doc_path = dir.join(format!("{tag}.json"));
    let wall_path = dir.join(format!("{tag}.wallns"));
    let prov_lib = format!("{OPT_LIB}/libcrypto.so.3");
    let mut inner = format!("start=$(date +%s%N); '{}'", flood.to_string_lossy());
    for a in args {
        inner.push(' ');
        inner.push_str(a);
    }
    inner.push_str(&format!(
        "; rc=$?; end=$(date +%s%N); echo $((end-start)) > '{}'; exit $rc",
        wall_path.to_string_lossy()
    ));
    let out = Command::new("timeout")
        .arg("400")
        .arg(bin)
        .args([
            "report",
            "--format",
            "json",
            "--out",
            &doc_path.to_string_lossy(),
            "--duration",
            "100",
            "--timeout",
            "120",
            "--provider",
            &prov_lib,
            "--builtin",
            "run",
            "--",
            "sh",
            "-c",
            &inner,
        ])
        .output()
        .unwrap();
    let code = out.status.code();
    assert!(
        matches!(code, Some(0) | Some(3)),
        "report run {tag} exit {code:?}: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let text = std::fs::read_to_string(&doc_path).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let wall_text = std::fs::read_to_string(&wall_path).unwrap();
    let wall_ns: u64 = wall_text.trim().parse().unwrap();
    assert!(wall_ns > 0, "{tag}: empty workload wall");
    (doc, wall_ns)
}

/// Matched wall-clock ratio: 3x flood-alone (A) vs 3x observed
/// workload-only (B) at 4x5000 ops. Scored (<=2x) only at >=100k
/// ops/s sustained; else recorded NOT_SCORED (R21 normative-unit
/// precedent: points below the rate are observations, not verdicts).
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_LAT_LIVE=1)"]
fn latency_wall_ratio_recorded() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("wall");
    let flood = build_flood(&dir);
    let mut a_ms = Vec::new();
    for _ in 0..3 {
        let t0 = std::time::Instant::now();
        let st = Command::new(&flood)
            .args(["4", "5000", "0", "sha256"])
            .output()
            .unwrap();
        assert!(st.status.success(), "flood-alone run failed");
        a_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    let mut b_ms = Vec::new();
    for i in 0..3 {
        let tag = format!("wall-b{i}");
        let (doc, wall_ns) = run_wall(&bin, &dir, &tag, &flood, &["4", "5000", "0", "sha256"]);
        assert_eq!(
            counters(&doc).get("count.ledger_delta"),
            Some(&0),
            "{tag}: ledger"
        );
        b_ms.push(wall_ns as f64 / 1_000_000.0);
    }
    a_ms.sort_by(|x, y| x.total_cmp(y));
    b_ms.sort_by(|x, y| x.total_cmp(y));
    let ratio = b_ms[1] / a_ms[1];
    let offered_per_s = 20_000.0 / (b_ms[1] / 1000.0);
    let scored = offered_per_s >= 100_000.0;
    if scored {
        assert!(
            ratio <= 2.0,
            "wall ratio {ratio} exceeds 2x at {offered_per_s}/s"
        );
    }
    let record = serde_json::json!({
        "a_ms": a_ms,
        "b_ms": b_ms,
        "ratio": ratio,
        "offered_per_s": offered_per_s,
        "scored": scored,
        "budget_2x": 2.0,
    });
    std::fs::write(
        out_dir().join("lat-wall.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

/// Cold/fresh-process cost: single-op observed run completes with
/// valid drain accounting; full wall + counters recorded.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_LAT_LIVE=1)"]
fn latency_cold_cost_recorded() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("cold");
    let flood = build_flood(&dir);
    let t0 = std::time::Instant::now();
    let doc = run_leg(&bin, &dir, "lat-cold", &flood, &["1", "1", "0", "sha256"]);
    let wall_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(
        !doc["sites"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "cold run observed no sites"
    );
    let c = counters(&doc);
    assert_eq!(c.get("count.ledger_delta"), Some(&0));
    let record = serde_json::json!({
        "wall_ms": wall_ms,
        "sites": doc["sites"].as_array().map(|s| s.len()),
        "drain_passes": c.get("count.drain_passes").copied(),
        "drain_pass_ns_total": c.get("count.drain_pass_ns_total").copied(),
        "drain_rss_bytes": c.get("count.drain_rss_bytes").copied(),
        "status": doc["completeness"]["status"],
    });
    std::fs::write(
        out_dir().join("lat-cold.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

/// Drain/memory under a medium-N workload (8-digest cycle): drain
/// counters present and consistent, RSS sampled, ledger clean.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_LAT_LIVE=1)"]
fn latency_drain_memory_recorded() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("drain");
    let flood = build_flood(&dir);
    let doc = run_leg(&bin, &dir, "lat-drain", &flood, &["4", "2000", "0", "many"]);
    let c = counters(&doc);
    assert_eq!(c.get("count.ledger_delta"), Some(&0));
    let passes = c.get("count.drain_passes").copied().unwrap_or(0);
    let total = c.get("count.drain_pass_ns_total").copied().unwrap_or(0);
    let max = c
        .get("count.drain_pass_ns_max")
        .copied()
        .unwrap_or(u64::MAX);
    let rss = c.get("count.drain_rss_bytes").copied().unwrap_or(0);
    assert!(passes >= 1, "drain passes must be >= 1");
    assert!(total >= max, "drain total {total} < max {max}");
    assert!(rss > 0, "drain RSS must be sampled");
    let record = serde_json::json!({
        "sites": doc["sites"].as_array().map(|s| s.len()),
        "passes": passes,
        "pass_ns_total": total,
        "pass_ns_max": max,
        "rss_bytes": rss,
        "status": doc["completeness"]["status"],
    });
    std::fs::write(
        out_dir().join("lat-drain.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
    std::fs::copy(
        dir.join("lat-drain.json"),
        out_dir().join("lat-drain-doc.json"),
    )
    .unwrap();
}
