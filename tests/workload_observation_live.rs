//! Workload-observation live leg (NOT RUN in CI: needs caps +
//! phase-2 objects + OSSL_WORKLOAD_OBSERVATION_LIVE=1 on the live lane).
//!
//! Regression pins for the 5A phase-2 zero-call gates (P2-I5; fix round 4
//! corrects the round-3 account). The phase-2 gate JSONs showed exactly 1
//! attached site (an off-path libc candidate) with 0 calls because those
//! gates observed the SHELL as the owned PID (`run -- sh -c 'openssl ...'`).
//! Discovery follows argv[0] (`sh` + libc only) and the one-process design
//! observes the owned PID only: "Forks, children, process replacement and
//! later numeric PID reuse do not acquire execution coverage" (docs/usage.md).
//! Paired controls on one observer binary reproduce both signatures (shell:
//! 1 site / 0 calls; direct: 2857 sites / 11572 calls), so the round-3
//! stale-binary attribution is withdrawn. Zero-calls-for-sh is CORRECT
//! behavior, not a product bug.
//!
//! Gate-scope rule (follows from the one-process contract): execution-
//! observation evidence MUST use direct-exec form (`run -- /usr/bin/openssl
//! ...`) so the owned PID is the workload binary itself; shell-form gates are
//! valid only for noninterference (oracle match) or where shell observation
//! is the explicit intent.
//!
//! `digest_workload_observes_execution_with_oracle_agreement` pins the healthy
//! direct-exec path end to end. `shell_form_observes_owned_shell_only` pins
//! the owned-PID boundary with paired shell/direct runs on one input.

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

fn site_keys(gate: &serde_json::Value) -> std::collections::BTreeSet<(String, u64)> {
    gate.get("sites")
        .and_then(|s| s.as_array())
        .map(|sites| {
            sites
                .iter()
                .map(|s| {
                    (
                        s.get("object")
                            .and_then(|o| o.as_str())
                            .unwrap_or("?")
                            .to_string(),
                        s.get("offset").and_then(|o| o.as_u64()).unwrap_or(u64::MAX),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn first_line_digest(text: &str) -> &str {
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().last())
        .unwrap_or("?")
}

fn gate_summary(gate: &serde_json::Value) -> (usize, u64, usize, String) {
    let sites = gate
        .get("sites")
        .and_then(|s| s.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let calls = sum_calls(gate);
    let fenced = gate
        .get("fenced")
        .and_then(|f| f.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let disposition = gate
        .get("disposition")
        .and_then(|d| d.get("outcome"))
        .and_then(|o| o.as_str())
        .unwrap_or("?")
        .to_string();
    (sites, calls, fenced, disposition)
}

#[test]
#[ignore = "live lane only (needs caps + phase-2 objects + OSSL_WORKLOAD_OBSERVATION_LIVE=1)"]
fn shell_form_observes_owned_shell_only() {
    let Some((bin, obs, cnt)) = prereqs() else {
        return;
    };
    let dir = stage("shell-vs-direct");
    // One deterministic 64 KiB input for both legs (same bytes, two forms).
    let input: Vec<u8> = (0..65536u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    let input_path = dir.join("input.bin");
    std::fs::write(&input_path, &input).unwrap();
    let input_arg = input_path.to_str().unwrap().to_string();

    let run_leg = |tag: &str, argv: &[String]| -> (serde_json::Value, String) {
        let gate_path = dir.join(format!("gate-{tag}.json"));
        let workload_path = dir.join(format!("workload-{tag}.log"));
        let mut cmd = Command::new(&bin);
        cmd.args([
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
        ]);
        for a in argv {
            cmd.arg(a);
        }
        let status = cmd.status().expect("run osslscope check");
        eprintln!("check exit ({tag}): {status}");
        let gate: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&gate_path).unwrap()).unwrap();
        let workload = std::fs::read_to_string(&workload_path).unwrap();
        (gate, workload)
    };

    // Same openssl binary, same input, same gate flags; only the owned PID
    // differs (openssl directly vs sh with openssl as a descendant).
    let (direct_gate, direct_workload) = run_leg(
        "direct",
        &[
            "/usr/bin/openssl".to_string(),
            "dgst".to_string(),
            "-sha256".to_string(),
            input_arg.clone(),
        ],
    );
    let shell_script = format!("/usr/bin/openssl dgst -sha256 {input_arg}; echo WORKLOAD_EXIT=$?");
    let (shell_gate, shell_workload) = run_leg(
        "shell",
        &["/bin/sh".to_string(), "-c".to_string(), shell_script],
    );

    let (direct_sites, direct_calls, direct_fenced, direct_disp) = gate_summary(&direct_gate);
    let (shell_sites, shell_calls, shell_fenced, shell_disp) = gate_summary(&shell_gate);
    eprintln!(
        "direct: sites={direct_sites} calls={direct_calls} fenced={direct_fenced} disposition={direct_disp}"
    );
    eprintln!(
        "shell: sites={shell_sites} calls={shell_calls} fenced={shell_fenced} disposition={shell_disp}"
    );

    // Both workloads run to exit (shell exit covers its openssl child).
    assert_eq!(direct_disp, "exited", "direct workload must run to exit");
    assert_eq!(shell_disp, "exited", "shell workload must run to exit");
    assert_eq!(direct_fenced, 0, "direct digest leg must not fence");
    assert_eq!(shell_fenced, 0, "shell digest leg must not fence");

    // Independent oracle: both observed digests match an unobserved run.
    // This proves the shell's openssl DESCENDANT ran healthy even though
    // its calls are (correctly) unobserved.
    let plain = Command::new("/usr/bin/openssl")
        .args(["dgst", "-sha256", &input_arg])
        .output()
        .expect("oracle openssl run");
    assert!(plain.status.success());
    let oracle = String::from_utf8(plain.stdout).unwrap();
    let oracle_digest = oracle.split_whitespace().last().unwrap_or("?");
    assert_eq!(
        first_line_digest(&direct_workload),
        oracle_digest,
        "direct digest must match unobserved oracle"
    );
    assert_eq!(
        first_line_digest(&shell_workload),
        oracle_digest,
        "shell-leg digest (from unobserved descendant) must match oracle"
    );
    assert!(
        shell_workload.contains("WORKLOAD_EXIT=0"),
        "shell leg must prove its openssl child exited 0"
    );

    // Owned-PID boundary: direct observes openssl (many sites, many calls);
    // shell observes sh+libc only (strictly fewer sites, zero calls — the
    // descendant's crypto execution never leaks into the owned-PID document).
    assert!(
        !direct_gate
            .get("sites")
            .and_then(|s| s.as_array())
            .unwrap()
            .is_empty()
    );
    assert!(direct_calls > 0, "direct leg must record openssl calls");
    assert!(shell_sites > 0, "shell leg must attach to shell sites");
    assert!(
        shell_sites < direct_sites,
        "shell (sh+libc) must discover strictly fewer sites than direct (openssl closure)"
    );
    assert_eq!(
        shell_calls, 0,
        "shell leg must record zero calls: descendant crypto is out of owned-PID scope"
    );
    let direct_set = site_keys(&direct_gate);
    let shell_set = site_keys(&shell_gate);
    assert!(
        shell_set.iter().all(|k| direct_set.contains(k)),
        "every shell-observed site must also appear under direct observation (subset)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
