//! Workload-observation live leg (NOT RUN in CI: needs caps +
//! phase-2 objects + OSSL_WORKLOAD_OBSERVATION_LIVE=1 on the live lane).
//!
//! Regression pin for the 5A phase-2 zero-call gates: the phase-2 gate
//! JSONs showed exactly 1 attached site (an off-path libc candidate)
//! with 0 calls, because the gates ran a stale `check` binary whose
//! discovery scope covered libc only. Every binary since discovers the
//! full ~2857-site scope with 10k+ calls on the same workload. This
//! test pins the healthy path end to end: `check run -- openssl dgst`
//! must observe a non-empty site set with a positive call total, an
//! exited disposition, no fenced generations, and a workload digest
//! that agrees with an unobserved re-run (observation + execution).

use std::path::PathBuf;
use std::process::Command;

fn gated() -> Option<()> {
    if std::env::var("OSSL_WORKLOAD_OBSERVATION_LIVE").unwrap_or_default() != "1" {
        eprintln!("workload observation live: set OSSL_WORKLOAD_OBSERVATION_LIVE=1; skipping");
        return None;
    }
    Some(())
}

fn prereqs() -> Option<(PathBuf, PathBuf, PathBuf)> {
    gated()?;
    let id = Command::new("id").arg("-u").output();
    match id {
        Ok(o) if o.status.success() && o.stdout.starts_with(b"0") => {}
        _ => {
            eprintln!("SKIP workload observation: need root (run under sudo -n)");
            return None;
        }
    }
    if !Command::new("/usr/bin/openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        eprintln!("SKIP workload observation: no /usr/bin/openssl");
        return None;
    }
    let obs = std::env::var_os("OSSL_PROVIDER_OBSERVATION_TEST_BPF");
    let cnt = std::env::var_os("OSSLSCOPE_FOCUSED_COUNT_OBJECT");
    if obs.is_none() || cnt.is_none() {
        eprintln!(
            "SKIP workload observation: set OSSL_PROVIDER_OBSERVATION_TEST_BPF + OSSLSCOPE_FOCUSED_COUNT_OBJECT"
        );
        return None;
    }
    let (obs, cnt) = (PathBuf::from(obs.unwrap()), PathBuf::from(cnt.unwrap()));
    if !obs.is_file() || !cnt.is_file() {
        eprintln!("SKIP workload observation: BPF objects missing");
        return None;
    }
    Some((PathBuf::from(env!("CARGO_BIN_EXE_osslscope")), obs, cnt))
}

fn stage(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "osslscope-workloadobs-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sum_calls(value: &serde_json::Value) -> u64 {
    value
        .get("sites")
        .and_then(|s| s.as_array())
        .map(|sites| {
            sites
                .iter()
                .map(|s| {
                    s.get("calls")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0)
}

#[test]
#[ignore = "live lane only (needs caps + phase-2 objects + OSSL_WORKLOAD_OBSERVATION_LIVE=1)"]
fn digest_workload_observes_execution_with_oracle_agreement() {
    let Some((bin, obs, cnt)) = prereqs() else {
        return;
    };
    let dir = stage("dgst");
    // Deterministic 64 KiB input (pattern, not random: stable across runs).
    let input: Vec<u8> = (0..65536u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    let input_path = dir.join("input.bin");
    std::fs::write(&input_path, &input).unwrap();
    let gate_path = dir.join("gate.json");
    let workload_path = dir.join("workload.log");

    let status = Command::new(&bin)
        .args([
            "check",
            "--observation-object",
            obs.to_str().unwrap(),
            "--count-object",
            cnt.to_str().unwrap(),
            "--duration",
            "20",
            "--timeout",
            "60",
            "--format",
            "json",
            "--out",
            gate_path.to_str().unwrap(),
            "--workload-out",
            workload_path.to_str().unwrap(),
            "--deny-weak",
            "run",
            "--",
            "/usr/bin/openssl",
            "dgst",
            "-sha256",
            input_path.to_str().unwrap(),
        ])
        .status()
        .expect("run osslscope check");
    // The verdict exit code is NOT pinned here (deny-weak inconclusive
    // semantics may evolve); the observation facts below are the pin.
    eprintln!("check exit: {status}");

    let gate: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&gate_path).unwrap()).unwrap();
    let sites = gate.get("sites").and_then(|s| s.as_array()).unwrap();
    let calls = sum_calls(&gate);
    let fenced = gate
        .get("fenced")
        .and_then(|f| f.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let disposition = gate
        .get("disposition")
        .and_then(|d| d.get("outcome"))
        .and_then(|o| o.as_str())
        .unwrap_or("?");
    eprintln!(
        "observed: sites={} calls={} fenced={} disposition={disposition}",
        sites.len(),
        calls,
        fenced
    );
    assert_eq!(disposition, "exited", "workload must run to exit");
    assert!(!sites.is_empty(), "healthy discovery observes sites");
    assert!(calls > 0, "healthy observation records calls");
    assert_eq!(fenced, 0, "digest workload must not fence");

    // Independent oracle: the observed digest must match an unobserved run.
    let observed = std::fs::read_to_string(&workload_path).unwrap();
    let plain = Command::new("/usr/bin/openssl")
        .args(["dgst", "-sha256", input_path.to_str().unwrap()])
        .output()
        .expect("oracle openssl run");
    assert!(plain.status.success());
    let oracle = String::from_utf8(plain.stdout).unwrap();
    let observed_digest = observed.split_whitespace().last().unwrap_or("?");
    let oracle_digest = oracle.split_whitespace().last().unwrap_or("?");
    assert_eq!(
        observed_digest, oracle_digest,
        "observed digest must match unobserved oracle"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
