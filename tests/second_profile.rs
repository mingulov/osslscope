//! Second kernel/libc profile legs (NOT RUN in CI: need caps +
//! /opt/openssl-live + OSSL_PROFILE_LIVE=1 on the live lane).
//!
//! Profile-agnostic shape suite, executed once per profile in
//! strictly sequential single guests: doctor shape, attach smoke,
//! count-conservation spot, latency spot, and the build-id
//! receipt that drives enrollment.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const OPT_CRYPTO: &str = "/opt/openssl-live/lib64/libcrypto.so";
const OPT_INC: &str = "/opt/openssl-live/include";
const OPT_LIB: &str = "/opt/openssl-live/lib64";

fn gated() -> Option<()> {
    if std::env::var("OSSL_PROFILE_LIVE").unwrap_or_default() != "1" {
        eprintln!("profile live leg: set OSSL_PROFILE_LIVE=1; skipping");
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
        eprintln!("SKIP profile: no gcc");
        return None;
    }
    if !Path::new(OPT_CRYPTO).exists() {
        eprintln!("SKIP profile: no {OPT_CRYPTO}");
        return None;
    }
    if !Path::new("/opt/openssl-live/include/openssl/evp.h").exists() {
        eprintln!("SKIP profile: no /opt openssl headers");
        return None;
    }
    Some(PathBuf::from(env!("CARGO_BIN_EXE_osslscope")))
}

fn stage(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "osslscope-profilelive-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn out_dir() -> PathBuf {
    match std::env::var("OSSL_PROFILE_OUT") {
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

/// One observed run: `report run` over the target; returns the
/// parsed doc + exit. Exit 0 or 3 (honest PARTIAL) both
/// acceptable; anything else (incl. wrapper timeout 124) fails
/// loudly.
///
/// The target libcrypto is named explicitly (`--provider` +
/// `--builtin`): pre-exec auto-discovery refuses the flood exe
/// as an unrecognized library and /bin/true as not OpenSSL
/// (cycle-1 exit-4 shape; T3-09cc413/T4-670a5f4/T6-32ff2d6
/// pinned fix). Explicit provider is the product-sanctioned
/// path (`docs/usage.md`); leg assertions unaffected.
fn run_report(bin: &Path, dir: &Path, tag: &str, target: &[&str]) -> (serde_json::Value, i32) {
    let doc_path = dir.join(format!("{tag}.json"));
    let mut cmd = vec![
        "report".to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--out".to_string(),
        doc_path.to_string_lossy().into_owned(),
        "--duration".to_string(),
        "60".to_string(),
        "--timeout".to_string(),
        "120".to_string(),
        "--provider".to_string(),
        format!("{OPT_LIB}/libcrypto.so.3"),
        "--builtin".to_string(),
        "run".to_string(),
        "--".to_string(),
    ];
    for a in target {
        cmd.push(a.to_string());
    }
    let out = Command::new("timeout")
        .arg("400")
        .arg(bin)
        .args(&cmd)
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 3,
        "report run {tag} exit {code}: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let text = std::fs::read_to_string(&doc_path).unwrap();
    (serde_json::from_str(&text).unwrap(), code)
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

/// Doctor runs with an orderly shape: exit 0 (ok) or 4
/// (fail-closed), with a `verdict:` line. Both recorded.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_PROFILE_LIVE=1)"]
fn profile_doctor_shape() {
    let Some(bin) = prereqs() else {
        return;
    };
    let out = Command::new(&bin).arg("doctor").output().unwrap();
    let code = out.status.code().unwrap_or(-1);
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        code == 0 || code == 4,
        "doctor exit {code} (want 0 ok or 4 fail-closed): {text:?}"
    );
    let verdict = text
        .lines()
        .find(|l| l.contains("verdict:"))
        .unwrap_or("")
        .to_string();
    assert!(
        !verdict.is_empty(),
        "doctor printed no verdict line: {text:?}"
    );
    let record = serde_json::json!({"exit": code, "verdict": verdict});
    std::fs::write(
        out_dir().join("profile-doctor.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

/// Attach smoke: observe `/bin/true`; the doc parses and carries
/// a completeness status. Exit recorded.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_PROFILE_LIVE=1)"]
fn profile_attach_smoke() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("smoke");
    let (doc, code) = run_report(&bin, &dir, "profile-smoke", &["/bin/true"]);
    assert!(
        doc["completeness"]["status"].is_string(),
        "smoke doc has no status"
    );
    let record = serde_json::json!({"exit": code, "status": doc["completeness"]["status"]});
    std::fs::write(
        out_dir().join("profile-smoke.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}
/// Conservation spot: 2x500 flood observes sites with a clean
/// ledger on this profile.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_PROFILE_LIVE=1)"]
fn profile_conservation_spot() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("cons");
    let flood = build_flood(&dir);
    let flood_s = flood.to_string_lossy().into_owned();
    let (doc, code) = run_report(
        &bin,
        &dir,
        "profile-cons",
        &[&flood_s, "2", "500", "0", "sha256"],
    );
    assert!(
        !doc["sites"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "conservation spot observed no sites"
    );
    assert_eq!(counters(&doc).get("count.ledger_delta"), Some(&0));
    let record = serde_json::json!({
        "exit": code,
        "sites": doc["sites"].as_array().map(|s| s.len()),
        "status": doc["completeness"]["status"],
    });
    std::fs::write(
        out_dir().join("profile-cons.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

/// Latency spot: the same shape run carries a non-empty measured
/// histogram (presence only; scoring is Task 6's).
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_PROFILE_LIVE=1)"]
fn profile_latency_spot() {
    let Some(bin) = prereqs() else {
        return;
    };
    let dir = stage("latspot");
    let flood = build_flood(&dir);
    let flood_s = flood.to_string_lossy().into_owned();
    let (doc, _) = run_report(
        &bin,
        &dir,
        "profile-lat",
        &[&flood_s, "2", "500", "0", "sha256"],
    );
    let c = counters(&doc);
    let samples = c.get("count.lat_samples").copied().unwrap_or(0);
    assert!(samples > 0, "latency spot measured no samples");
    let mut sum = 0u64;
    for k in 0..16 {
        sum += c
            .get(&format!("count.lat_bucket_{k:02}"))
            .copied()
            .unwrap_or(0);
    }
    assert_eq!(sum, samples, "buckets must sum to samples");
    let record = serde_json::json!({
        "samples": samples,
        "median_ns": c.get("count.lat_median_ns").copied(),
        "status": doc["completeness"]["status"],
    });
    std::fs::write(
        out_dir().join("profile-lat.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

/// Build-id receipt: captures /opt + system libcrypto identities
/// (build-id hex + openssl version) for the enrollment step.
/// Formats asserted; values recorded.
#[test]
#[ignore = "live lane only (needs caps + /opt/openssl-live + OSSL_PROFILE_LIVE=1)"]
fn profile_buildid_receipt() {
    let Some(_) = prereqs() else {
        return;
    };
    if !have("readelf", &["--version"]) {
        eprintln!("SKIP buildid: no readelf");
        return;
    }
    let opt_id = build_id_of(OPT_CRYPTO);
    assert_build_id(&opt_id, "opt");
    let from_ldconfig = Command::new("ldconfig")
        .args(["-p"])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find(|line| line.contains("libcrypto.so.3"))
                .and_then(|line| line.split("=>").nth(1))
                .map(|p| p.trim().to_string())
        });
    let sys_path = from_ldconfig.or_else(|| {
        [
            "/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib64/libcrypto.so.3",
            "/lib64/libcrypto.so.3",
        ]
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| p.to_string())
    });
    let (sys_path, sys_id) = match sys_path {
        Some(p) => {
            let id = build_id_of(&p);
            (Some(p), Some(id))
        }
        None => (None, None),
    };
    if let Some(id) = &sys_id {
        assert_build_id(id, "system");
    }
    let opt_ver = Command::new("/opt/openssl-live/bin/openssl")
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let sys_ver = Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let record = serde_json::json!({
        "opt": {"path": OPT_CRYPTO, "build_id": opt_id, "openssl_version": opt_ver},
        "system": {"path": sys_path, "build_id": sys_id, "openssl_version": sys_ver},
    });
    std::fs::write(
        out_dir().join("profile-buildid.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

fn build_id_of(path: &str) -> String {
    let out = Command::new("readelf").args(["-n", path]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .find(|l| l.contains("Build ID:"))
        .and_then(|l| l.split("Build ID:").nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn assert_build_id(id: &str, tag: &str) {
    assert!(
        (16..=128).contains(&id.len()) && id.chars().all(|c| c.is_ascii_hexdigit()),
        "{tag} build-id malformed: {id:?}"
    );
}
