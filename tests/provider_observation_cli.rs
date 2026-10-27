// SPDX-License-Identifier: GPL-3.0-or-later
//! Public command controls without privileged target attachment.
use std::{
    fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osslscope-provider-cli-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        // An isolated executable has no automatic companion. Lookup must never
        // fall back to the caller's cwd, environment, or another build tree.
        fs::copy(env!("CARGO_BIN_EXE_osslscope"), path.join("osslscope")).unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        Command::new(self.0.join("osslscope"))
    }
    fn cli(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn records(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("provider NDJSON"))
        .collect()
}
fn redacted(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("PRIVATE_CANARY"), "{text}");
        assert!(!text.contains("0x"), "{text}");
        assert!(!text.contains("panicked"), "{text}");
    }
}
#[test]
fn help_describes_opt_in_observation_before_scope_acquisition() {
    let f = Fixture::new();
    for command in ["scan", "inspect"] {
        let output = f.cli(&[command, "--observe-providers", "--help"]);
        assert_eq!(output.status.code(), Some(0));
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--observe-providers"));
        assert!(help.contains("30"));
        assert!(help.contains("execution"));
    }
}
#[test]
fn malformed_and_repeated_flags_are_finite_before_resources() {
    let f = Fixture::new();
    for args in [
        vec!["scan", "--observe-providers", "--pid", "PRIVATE_CANARY"],
        vec![
            "scan",
            "--observe-providers",
            "--watch",
            "--duration",
            "NaN",
        ],
        vec![
            "scan",
            "--observe-providers",
            "--watch",
            "--interval",
            "0.049",
        ],
        vec!["scan", "--observe-providers", "--duration", "0.1"],
        vec!["scan", "--observe-providers", "--observe-providers"],
        vec![
            "scan",
            "--observe-providers",
            "--module",
            "/PRIVATE_CANARY",
            "--bogus",
        ],
        vec!["inspect", "--observe-providers"],
        vec![
            "inspect",
            "--observe-providers",
            "--module",
            "/PRIVATE_CANARY",
        ],
        vec!["doctor", "--discovery", "--libcrypto", "/PRIVATE_CANARY"],
    ] {
        let output = f.cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.len() < 512);
        redacted(&output);
    }
}
#[test]
fn unavailable_companion_keeps_inventory_and_history_unknown() {
    let f = Fixture::new();
    let pid = std::process::id().to_string();
    let output = f.cli(&[
        "scan",
        "--pid",
        &pid,
        "--observe-providers",
        "--watch",
        "--duration",
        "0.12",
        "--interval",
        "0.05",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let docs = records(&output);
    let first = &docs[0];
    assert_eq!(first["schema_version"], "osslscope.discovery.provider.v1");
    assert_eq!(first["record"], "snapshot");
    assert_eq!(
        first["snapshot"]["schema_version"],
        "osslscope.discovery.v1"
    );
    assert_eq!(first["snapshot"]["processes"][0]["pid"], std::process::id());
    assert_eq!(first["capabilities"]["historical_activation"], "unknown");
    assert_eq!(first["capabilities"]["execution"], "not_observed");
    assert_eq!(first["capabilities"]["tracing"], "unavailable");
    assert!(
        first["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "bpf_unavailable")
    );
    assert!(first["facts"].as_array().unwrap().is_empty());
    assert_eq!(docs.last().unwrap()["record"], "end");
    assert_eq!(docs.last().unwrap()["status"], 3);
    assert_eq!(docs.last().unwrap()["reason"], "duration");
    assert!(output.stdout.len() < 1_048_576);
    redacted(&output);
}
#[test]
fn no_usable_scope_is_exit_four() {
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        "2147483647",
        "--observe-providers",
        "--watch",
        "--duration",
        "0.05",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(records(&output).last().unwrap()["status"], 4);
    redacted(&output);
}
#[test]
fn human_output_carries_the_same_finite_facts_and_gaps() {
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        &std::process::id().to_string(),
        "--observe-providers",
        "--watch",
        "--duration",
        "0.05",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "bpf_unavailable",
        "unknown",
        "not_observed",
        "snapshot",
        "end",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    redacted(&output);
}
#[test]
fn output_failure_stops_with_internal_error() {
    let f = Fixture::new();
    let output = f
        .command()
        .args([
            "scan",
            "--pid",
            &std::process::id().to_string(),
            "--observe-providers",
            "--watch",
            "--duration",
            "1",
            "--json",
        ])
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    redacted(&output);
}
#[test]
fn observer_cancellation_emits_end_and_returns_partial() {
    let f = Fixture::new();
    let mut child = f
        .command()
        .args([
            "scan",
            "--pid",
            &std::process::id().to_string(),
            "--observe-providers",
            "--watch",
            "--duration",
            "5",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    assert!(
        out.read_line(&mut line).unwrap() > 0,
        "must emit initial inventory"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap()["record"],
        "snapshot"
    );
    // Signal only the observer child, never a selected workload.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(started.elapsed() < Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut last = None;
    for line in out.lines() {
        last = Some(serde_json::from_str::<serde_json::Value>(&line.unwrap()).unwrap());
    }
    assert_eq!(child.wait().unwrap().code(), Some(3));
    assert_eq!(last.as_ref().unwrap()["reason"], "interrupted");
}
#[test]
fn discovery_doctor_does_not_require_a_build_catalogue() {
    let f = Fixture::new();
    let output = f.cli(&["doctor", "--discovery", "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["schema_version"], "osslscope.discovery.provider.v1");
    assert_eq!(doc["record"], "doctor");
    assert_eq!(doc["capabilities"]["inventory"], "available");
    assert_eq!(doc["capabilities"]["companion"], "unavailable");
    assert!(doc.get("profile").is_none());
    redacted(&output);
}

#[test]
fn build_dev_copies_the_emitted_companion_beside_the_actual_host_artifact() {
    use std::os::unix::fs::PermissionsExt as _;
    let f = Fixture::new();
    let root = f.0.join("source");
    fs::create_dir_all(root.join("scripts")).unwrap();
    fs::create_dir_all(root.join("crates/ebpf")).unwrap();
    fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build-dev.sh"),
        root.join("scripts/build-dev.sh"),
    )
    .unwrap();
    let tools = f.0.join("tools");
    fs::create_dir(&tools).unwrap();
    let cargo = r#"#!/usr/bin/python3
import json,os,pathlib,sys
args=sys.argv[1:]
root=pathlib.Path(os.environ['PROVIDER_BUILD_FIXTURE'])
if '--version' in args: print('cargo 1.88.0'); sys.exit(0)
if 'metadata' in args: print(json.dumps({'target_directory': str(root/'custom target')})); sys.exit(0)
assert 'build' in args and '--locked' in args and '--offline' in args
bins=[args[i+1] for i,a in enumerate(args) if a=='--bin'] or ['osslscope']
for name in bins:
    p=root/'custom target'/('bpfel-unknown-none/release' if name!='osslscope' else 'custom-triple/debug')/name
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(('fresh '+name).encode()); p.chmod(0o755)
    print(json.dumps({'reason':'compiler-artifact','target':{'name':name,'kind':['bin']},'executable':str(p)}))
"#;
    for (name, source) in [
        ("cargo", cargo),
        ("rustc", "#!/bin/sh\necho 'rustc 1.88.0'\n"),
        ("rustup", "#!/bin/sh\necho 'rust-src'\n"),
        ("bpf-linker", "#!/bin/sh\necho 'bpf-linker 0.10.4'\n"),
    ] {
        fs::write(tools.join(name), source).unwrap();
        fs::set_permissions(tools.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let output = Command::new("sh")
        .arg(root.join("scripts/build-dev.sh"))
        .args(["--offline", "--jobs", "2"])
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("PROVIDER_BUILD_FIXTURE", &f.0)
        .env("CARGO_TARGET_DIR", f.0.join("custom target"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let copied =
        f.0.join("custom target/custom-triple/debug/osslscope-provider-observation");
    assert_eq!(
        fs::read(copied).expect("automatic sibling companion"),
        b"fresh osslscope-provider-observation"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("target/dev-build-manifest.json")).unwrap())
            .unwrap();
    assert!(
        manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["bin"] == "osslscope-provider-observation")
    );
}

#[test]
fn malformed_companion_is_finite_and_does_not_hide_inventory() {
    let f = Fixture::new();
    fs::write(
        f.0.join("osslscope-provider-observation"),
        b"PRIVATE_CANARY_not_an_object",
    )
    .unwrap();
    let output = f.cli(&[
        "scan",
        "--pid",
        &std::process::id().to_string(),
        "--observe-providers",
        "--watch",
        "--duration",
        "0.05",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let docs = records(&output);
    assert!(
        docs[0]["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "invalid_object")
    );
    assert!(
        !docs[0]["snapshot"]["processes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    redacted(&output);
    let output = f.cli(&["doctor", "--discovery", "--json"]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["capabilities"]["companion"],
        "unavailable"
    );
    redacted(&output);
}

#[test]
fn public_c_fixtures_remain_inventory_when_observation_is_unavailable() {
    let f = Fixture::new();
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (source, output, flags) in [
        ("provider_observation.c", "stimulus", vec!["-O2"]),
        (
            "provider_observation_provider.c",
            "PRIVATE_CANARY_provider.so",
            vec!["-shared", "-fPIC", "-O2"],
        ),
    ] {
        let mut command = Command::new("cc");
        command
            .args(flags)
            .arg("-o")
            .arg(f.0.join(output))
            .arg(fixtures.join(source));
        if source == "provider_observation.c" {
            command.args(["-lcrypto", "-ldl"]);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let mut app = Command::new(f.0.join("stimulus"))
        .arg(f.0.join("PRIVATE_CANARY_provider.so"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(app.stdout.as_mut().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let output = f.cli(&[
        "scan",
        "--pid",
        &app.id().to_string(),
        "--observe-providers",
        "--watch",
        "--duration",
        "0.05",
        "--json",
    ]);
    drop(app.stdin.take());
    assert!(app.wait().unwrap().success());
    assert_eq!(output.status.code(), Some(3));
    let docs = records(&output);
    let process = &docs[0]["snapshot"]["processes"][0];
    assert!(
        process["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["info"]["kind"] == "provider_module")
    );
    assert_eq!(process["provider_activation"], "unknown");
    assert_eq!(process["execution"], "not_observed");
    assert!(
        docs.iter()
            .filter_map(|r| r["facts"].as_array())
            .all(Vec::is_empty)
    );
    redacted(&output);
}
