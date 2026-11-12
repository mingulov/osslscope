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
    // v0.6.0 renders the sample line as `provider sample:` (the old
    // `snapshot N:` tick dump is gone); expecting the bare word
    // `snapshot` only passed via the timing-dependent
    // `snapshot_lag` gap and flaked on CI. Pin the contract line.
    for expected in [
        "bpf_unavailable",
        "unknown",
        "not_observed",
        "provider sample:",
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
    // Exercise the real source snapshot helper against a tiny owned sysroot.
    // These are fake compiler outputs; no Rust or BPF compilation runs here.
    fs::create_dir(root.join("packaging")).unwrap();
    fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/source_payload.py"),
        root.join("packaging/source_payload.py"),
    )
    .unwrap();
    let library = f.0.join("sysroot/lib/rustlib/src/rust/library/core/src");
    fs::create_dir_all(&library).unwrap();
    fs::write(library.join("lib.rs"), b"// fixed fake runtime source\n").unwrap();
    let tools = f.0.join("tools");
    fs::create_dir(&tools).unwrap();
    let cargo = r#"#!/usr/bin/python3
import json,os,pathlib,sys
args=sys.argv[1:]
root=pathlib.Path(os.environ['PROVIDER_BUILD_FIXTURE'])
pin=args[0]
assert pin in ('+1.88.0', '+nightly-2026-05-20'), args
compiler=str(root/'tools'/pin[1:]/'rustc')
assert os.environ['RUSTC'] == compiler
assert os.environ['CARGO_BUILD_RUSTC'] == compiler
assert os.environ['CARGO_ENCODED_RUSTFLAGS'] == ''
if '--version' in args: print('cargo '+('1.88.0' if pin=='+1.88.0' else '1.91.0-nightly')); sys.exit(0)
if 'metadata' in args: print(json.dumps({'target_directory': str(root/'custom target')})); sys.exit(0)
assert 'build' in args and '--locked' in args and '--offline' in args
bins=[args[i+1] for i,a in enumerate(args) if a=='--bin'] or ['osslscope']
assert (pin=='+1.88.0') == (bins==['osslscope'])
for name in bins:
    p=root/'custom target'/('bpfel-unknown-none/release' if name!='osslscope' else 'custom-triple/debug')/name
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(('fresh '+name).encode()); p.chmod(0o755)
    print(json.dumps({'reason':'compiler-artifact','target':{'name':name,'kind':['bin']},'executable':str(p)}))
"#;
    let rustup = r#"#!/usr/bin/python3
import os,pathlib,sys
root=pathlib.Path(os.environ['PROVIDER_BUILD_FIXTURE'])
args=sys.argv[1:]
if len(args)==4 and args[:2]==['which','--toolchain'] and args[3]=='rustc':
    assert args[2] in ('1.88.0','nightly-2026-05-20')
    print(root/'tools'/args[2]/'rustc')
elif args==['component','list','--toolchain','nightly-2026-05-20','--installed']:
    print('rust-src')
else:
    raise AssertionError(args)
"#;
    let rustc = r#"#!/usr/bin/python3
import os,pathlib,sys
root=pathlib.Path(os.environ['PROVIDER_BUILD_FIXTURE'])
pin=pathlib.Path(sys.argv[0]).parent.name
if sys.argv[1:]==['--version']:
    print('rustc '+('1.88.0 (fake-host)' if pin=='1.88.0' else '1.91.0-nightly (fake-bpf)'))
elif sys.argv[1:]==['--print','sysroot']:
    assert pin=='nightly-2026-05-20'
    print(root/'sysroot')
else:
    raise AssertionError(sys.argv[1:])
"#;
    for pin in ["1.88.0", "nightly-2026-05-20"] {
        fs::create_dir(tools.join(pin)).unwrap();
        fs::write(tools.join(pin).join("rustc"), rustc).unwrap();
        fs::set_permissions(
            tools.join(pin).join("rustc"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    for (name, source) in [
        ("cargo", cargo),
        ("rustc", rustc),
        ("rustup", rustup),
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
        fs::read(&copied).expect("automatic sibling companion"),
        b"fresh osslscope-provider-observation"
    );
    assert_ne!(
        fs::metadata(&copied).unwrap().permissions().mode() & 0o111,
        0
    );
    let focused =
        f.0.join("custom target/custom-triple/debug/osslscope-focused-count");
    assert_eq!(
        fs::read(&focused).unwrap(),
        b"fresh osslscope-focused-count"
    );
    assert_ne!(
        fs::metadata(&focused).unwrap().permissions().mode() & 0o111,
        0
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
    // F-NEW-1 (R13 always-acquire; F7 canary-re-pin precedent):
    // the canary provider filename now LEGITIMATELY appears in
    // machine records — but ONLY under the D1 path-evidence keys
    // (`verified_path.path`, `maps_spelling.spelling`). Anywhere
    // else is a leak; stderr keeps the blanket ban.
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("0x"), "{text}");
    assert!(!text.contains("panicked"), "{text}");
    for line in text.lines() {
        let doc: serde_json::Value = serde_json::from_str(line).expect("provider NDJSON");
        fn walk(value: &serde_json::Value, parent: &str) {
            match value {
                serde_json::Value::Object(object) => {
                    for (key, child) in object {
                        walk(child, key);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        walk(item, parent);
                    }
                }
                serde_json::Value::String(text) => {
                    if text.contains("PRIVATE_CANARY") {
                        assert!(
                            parent == "path" || parent == "spelling",
                            "canary filename outside D1 path-evidence keys (key {parent:?}): {text}"
                        );
                    }
                }
                _ => {}
            }
        }
        walk(&doc, "");
    }
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(!err.contains("PRIVATE_CANARY"), "{err}");
    assert!(!err.contains("0x"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
}

#[test]
fn observe_providers_help_names_exit_codes() {
    let f = Fixture::new();
    for command in ["scan", "inspect"] {
        let output = f.cli(&[command, "--observe-providers", "--help"]);
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(
            help.contains("  exit 0:")
                && help.contains("  exit 1:")
                && help.contains("  exit 2:")
                && help.contains("  exit 3:")
                && help.contains("  exit 4:"),
            "{command} --observe-providers help must name exit codes, got: {help}"
        );
        assert!(
            help.contains("first run blocked?"),
            "{command} --observe-providers help must point first runs at doctor, got: {help}"
        );
    }
}

#[test]
fn observe_providers_help_lists_only_emittable_exits() {
    // Provider observation emits 0/1/2/3/4 only (policy exits
    // 10/11 are unemittable here); interruption lands on exit 3
    // per docs/provider-observation.md.
    let f = Fixture::new();
    for command in ["scan", "inspect"] {
        let output = f.cli(&[command, "--observe-providers", "--help"]);
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(
            !help.contains("exit 10"),
            "{command} help must not list unemittable exit 10, got: {help}"
        );
        assert!(
            !help.contains("exit 11"),
            "{command} help must not list unemittable exit 11, got: {help}"
        );
        assert!(
            help.contains("exit 3:") && help.contains("interruption"),
            "{command} help must land interruption on exit 3, got: {help}"
        );
    }
}

#[test]
fn no_usable_scope_exit4_names_reason_on_stderr() {
    // Deterministic exit 4: dead pid under provider observation.
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
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    let reasons: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("osslscope provider discovery:"))
        .collect();
    assert_eq!(reasons.len(), 1, "exactly one stderr reason, got: {stderr}");
    assert!(
        reasons[0].contains("unavailable"),
        "reason names the unavailable class, got: {stderr}"
    );
    assert_eq!(records(&output).last().unwrap()["status"], 4);
}

#[test]
fn human_snapshot_prints_identity_totals() {
    // Dead pid, human mode: the empty snapshot still totals identity.
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        "2147483647",
        "--observe-providers",
        "--watch",
        "--duration",
        "0.05",
    ]);
    assert_eq!(output.status.code(), Some(4));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("identity: no modules inventoried"),
        "identity totals on empty human snapshot, got: {text}"
    );
}

#[test]
fn human_watch_with_gaps_never_claims_blindness() {
    // Unprivileged initial snapshot carries gaps: the boundary stays
    // silent (fail closed). Under root the presence test owns the
    // assertion instead.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIP: absence needs an unprivileged gap fixture");
        return;
    }
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        &child.id().to_string(),
        "--observe-providers",
        "--watch",
        "--duration",
        "0.3",
    ]);
    child.kill().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("provider sample:"),
        "fixture precondition: sampled, got: {text}"
    );
    assert!(
        !text.contains("blindness:"),
        "no absence claim under gaps, got: {text}"
    );
}

#[test]
fn human_watch_states_blindness_once_before_sampling_when_verified() {
    // Root-only presence: the verified boundary prints once, before
    // the first sample record.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIP: verified scan needs root");
        return;
    }
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        &child.id().to_string(),
        "--observe-providers",
        "--watch",
        "--duration",
        "0.3",
    ]);
    child.kill().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let pos = text
        .find("blindness: no-mapped-openssl")
        .expect("blocker printed");
    let first_sample = text.find("provider sample:").expect("samples follow");
    assert!(pos < first_sample, "blocker must precede sampling");
    assert_eq!(
        text.matches("blindness: no-mapped-openssl").count(),
        1,
        "boundary printed once, got: {text}"
    );
}

#[test]
fn human_records_coalesce_gaps() {
    // Dead pid, human mode: inventory + observation gaps render grouped.
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        "2147483647",
        "--observe-providers",
        "--watch",
        "--duration",
        "0.05",
    ]);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("gaps (") && text.contains("total in"),
        "coalesced gap block, got: {text}"
    );
    assert!(
        !text.contains("  gap=\"") && !text.contains("  inventory_gap="),
        "no per-gap lines remain, got: {text}"
    );
}

#[test]
fn human_verbosity_adds_detail_only() {
    // v0.6.0 Task 2: -v/-vv gate human detail volume only — the
    // exit, stderr, and capability words match level 0 while
    // exports/counters appear and hashes stay short everywhere.
    let f = Fixture::new();
    let pid = std::process::id().to_string();
    let run = |extra: &[&str]| {
        let mut args = vec![
            "scan",
            "--pid",
            pid.as_str(),
            "--observe-providers",
            "--watch",
            "--duration",
            "0.05",
        ];
        args.extend(extra.iter().copied());
        f.cli(&args)
    };
    let base = run(&[]);
    let v1 = run(&["-v"]);
    let v2 = run(&["-vv"]);
    assert_eq!(base.status.code(), v1.status.code());
    assert_eq!(base.status.code(), v2.status.code());
    assert_eq!(base.stderr, v1.stderr);
    assert_eq!(base.stderr, v2.stderr);
    let t0 = String::from_utf8_lossy(&base.stdout).into_owned();
    let t1 = String::from_utf8_lossy(&v1.stdout).into_owned();
    let t2 = String::from_utf8_lossy(&v2.stdout).into_owned();
    // (-v exports ride module rows, which need inventoried
    // modules; container identity verification yields none here,
    // so the lib tests pin exports while live runs pin full
    // process state.)
    assert!(
        t1.contains("namespaces=") && t1.contains("modules="),
        "no -v process state, got: {t1}"
    );
    assert!(
        t2.contains("counters: read_bytes="),
        "no -vv counters, got: {t2}"
    );
    for (level, text) in [("0", &t0), ("1", &t1), ("2", &t2)] {
        assert!(!has_64_hex(text), "full hash at level {level}");
    }
    redacted(&v2);
}

#[test]
fn human_watch_repeated_snapshot_batches_heartbeat() {
    // W1 mirror: batch 1 renders full; a later identical batch
    // (no facts, same gaps, same snapshot state) heartbeats, and
    // the end record names the cumulative history.
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        "2147483647",
        "--observe-providers",
        "--watch",
        "--interval",
        "0.05",
        "--duration",
        "0.4",
    ]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains("provider sample:"),
        "first batch full, got: {text}"
    );
    assert!(
        text.contains("tick ") && text.contains("no changes"),
        "no heartbeat, got: {text}"
    );
    assert!(
        text.contains("cumulative="),
        "no cumulative word, got: {text}"
    );
    redacted(&output);
}

fn has_64_hex(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 64
        && (0..=bytes.len() - 64).any(|i| bytes[i..i + 64].iter().all(|b| b.is_ascii_hexdigit()))
}

#[test]
fn human_default_has_plain_header_without_jargon() {
    // v0.6.0 Task 4 (W2/W5): dead-pid provider watch renders the
    // plain-words header with none of the four jargon counters at
    // default; `-vv` restores the full technical detail. (The
    // honest `interval_unknown` line and per-fact `monotonic_ns`
    // need a live session, so lib tests pin them synthetically.)
    let f = Fixture::new();
    let run = |extra: &[&str]| {
        let mut args = vec![
            "scan",
            "--pid",
            "2147483647",
            "--observe-providers",
            "--watch",
            "--duration",
            "0.05",
        ];
        args.extend(extra.iter().copied());
        f.cli(&args)
    };
    let base = run(&[]);
    let v2 = run(&["-vv"]);
    assert_eq!(base.status.code(), v2.status.code());
    let t0 = String::from_utf8_lossy(&base.stdout).into_owned();
    assert!(
        t0.contains("provider sample: 0 modules, 0 facts"),
        "no plain header, got: {t0}"
    );
    for word in ["drain_lag_ns", "facts=", "tracing=", "monotonic_ns"] {
        assert!(!t0.contains(word), "{word} at default, got: {t0}");
    }
    assert!(!has_64_hex(&t0), "full hash at default");
    let t2 = String::from_utf8_lossy(&v2.stdout).into_owned();
    for word in ["drain_lag_ns=", "facts=", "tracing="] {
        assert!(t2.contains(word), "{word} missing at -vv, got: {t2}");
    }
    redacted(&base);
    redacted(&v2);
}

#[test]
fn v060_provider_watch_sigint_acks_once_with_interrupted_end() {
    // Live-pid watch like `observer_cancellation_emits_end_and_returns_partial`
    // (unprivileged host: no BPF session can attach, passive fallback — the
    // SIGINT leg below exercises the observe loop's cancel path only; live
    // legs stay guest-side for Task 6).
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
            "60",
            "--interval",
            "1",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // First record proves the observe loop is running (no sleep guess).
    let mut first = String::new();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    reader.read_line(&mut first).unwrap();
    assert!(first.contains("\"snapshot\""), "no first record: {first}");
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    // Drain stdout to EOF (child exit), then collect stderr + status.
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut reader, &mut rest).unwrap();
    drop(reader);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        err.matches("shutting down").count(),
        1,
        "ack count wrong: {err}"
    );
    assert!(
        rest.contains("\"interrupted\""),
        "no interrupt end: {first}{rest}"
    );
    assert!(rest.contains("\"record\":\"end\""), "no end record: {rest}");
}

fn spawn_tls_workload() -> std::process::Child {
    // Sleeper with libssl/libcrypto mapped (module rows expected;
    // a plain sleep maps no OpenSSL — a vacuous fixture).
    std::process::Command::new("python3")
        .args(["-c", "import ssl, time; time.sleep(120)"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn provider_json_snapshots_carry_path_evidence_by_default() {
    // F-NEW-1 (R13 always-acquire): provider NDJSON embedded
    // snapshots carry D1 path evidence by default — every module
    // carries verified-or-reason plus a maps spelling, never the
    // bare-null triple of the acquire-off shape.
    let mut workload = spawn_tls_workload();
    std::thread::sleep(Duration::from_millis(500));
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        &workload.id().to_string(),
        "--observe-providers",
        "--watch",
        "--duration",
        "0.12",
        "--interval",
        "0.05",
        "--json",
    ]);
    let _ = workload.kill();
    let _ = workload.wait();
    assert_eq!(output.status.code(), Some(3));
    let mut modules = 0;
    let mut evidenced = 0;
    for doc in records(&output)
        .iter()
        .filter(|doc| doc["record"] == "snapshot")
    {
        let processes = doc["snapshot"]["processes"].as_array();
        for module in processes
            .into_iter()
            .flatten()
            .flat_map(|p| p["modules"].as_array().into_iter().flatten())
        {
            modules += 1;
            assert!(
                module["verified_path"].is_null() != module["verified_path_unavailable"].is_null(),
                "bare-null triple without a D1 reason: {module}"
            );
            if !module["maps_spelling"].is_null() {
                evidenced += 1;
            }
        }
    }
    assert!(
        modules > 0 && evidenced > 0,
        "acquisition off: no D1 evidence in {modules} module records"
    );
    redacted(&output);
}

#[test]
fn provider_human_rows_carry_paths_by_default() {
    // F-NEW-1 (quiet contract + H8 precedent): provider human
    // module rows carry `path=`/`version=` and process lines
    // carry `comm=`/`exe=` by default.
    let mut workload = spawn_tls_workload();
    std::thread::sleep(Duration::from_millis(500));
    let f = Fixture::new();
    let output = f.cli(&[
        "scan",
        "--pid",
        &workload.id().to_string(),
        "--observe-providers",
        "--watch",
        "--duration",
        "0.12",
        "--interval",
        "0.05",
    ]);
    let _ = workload.kill();
    let _ = workload.wait();
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let rows: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("    sha256="))
        .collect();
    assert!(!rows.is_empty(), "no module rows, got: {text}");
    for row in &rows {
        assert!(
            row.contains("path=") && row.contains("version="),
            "row without path/version, got: {row}"
        );
    }
    let processes: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("  process "))
        .collect();
    assert!(!processes.is_empty(), "no process lines, got: {text}");
    for line in &processes {
        assert!(
            line.contains("comm=") && line.contains("exe="),
            "process line without comm/exe, got: {line}"
        );
    }
    redacted(&output);
}
