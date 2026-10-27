// SPDX-License-Identifier: GPL-3.0-or-later
//! Real CLI controls: passive metadata, finite diagnostics and numeric exits.
use sha2::{Digest as _, Sha256};
use std::fs;
use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "osslscope-cli-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn build(&self, name: &str, source: &str, shared: bool) -> PathBuf {
        let source_path = self.0.join(format!("{name}.c"));
        let output = self.0.join(name);
        fs::write(&source_path, source).unwrap();
        let mut command = Command::new("cc");
        if shared {
            command.args(["-shared", "-fPIC"]);
        }
        let result = command
            .arg("-o")
            .arg(&output)
            .arg(source_path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        output
    }
    fn module(&self) -> PathBuf {
        self.build("PRIVATE_CANARY_module", &format!(r#"
#include <stdio.h>
__attribute__((constructor)) static void marker(void) {{ FILE *f = fopen("{}", "w"); if (f) fclose(f); }}
int OSSL_provider_init(void) {{ return 1; }}
int PRIVATE_CANARY_symbol(void) {{ return 2; }}
"#, self.0.join("PRIVATE_CANARY_executed").display()), true)
    }
    fn child(&self, module: &PathBuf) -> OwnedChild {
        let executable = self.build(
            "child",
            r#"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    int fd = open(argv[1], O_RDONLY); struct stat st;
    if (fd < 0 || fstat(fd, &st)) return 2;
    if (mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED) return 3;
    close(fd); puts("ready"); fflush(stdout);
    while (getchar() != EOF) {} return 0;
}
"#,
            false,
        );
        let mut child = Command::new(executable)
            .arg(module)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "ready\n");
        OwnedChild(child)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        assert!(self.0.wait().unwrap().success());
    }
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(args)
        .output()
        .unwrap()
}
fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("structured discovery output")
}
fn redacted(output: &Output, fixture: &Fixture) {
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        assert!(!text.contains("PRIVATE_CANARY"), "{text}");
        assert!(!text.contains(fixture.0.to_str().unwrap()), "{text}");
    }
}
#[test]
fn scan_pid_json_needs_no_profile_or_bpf() {
    let f = Fixture::new();
    let module = f.module();
    let child = f.child(&module);
    let output = cli(&["scan", "--pid", &child.0.id().to_string(), "--json"]);
    assert!(matches!(output.status.code(), Some(0 | 3)));
    let doc = json(&output);
    assert_eq!(doc["schema_version"], "osslscope.discovery.v1");
    assert_eq!(doc["mode"], "snapshot");
    let process = &doc["processes"][0];
    assert_eq!(process["pid"], child.0.id());
    let hash = digest(&module);
    assert!(
        process["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["info"]["sha256"] == hash && m["info"]["kind"] == "provider_module")
    );
    redacted(&output, &f);
}
#[test]
fn inspect_module_is_passive_and_redacted() {
    let f = Fixture::new();
    let module = f.module();
    let output = cli(&["inspect", "--module", module.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let doc = json(&output);
    assert_eq!(doc["schema_version"], "osslscope.discovery.v1");
    assert_eq!(doc["mode"], "module");
    assert_eq!(doc["modules"][0]["kind"], "provider_module");
    assert_eq!(
        doc["modules"][0]["exports"],
        serde_json::json!(["ossl_provider_init"])
    );
    assert_eq!(doc["modules"][0]["sha256"], digest(&module));
    assert!(!f.0.join("PRIVATE_CANARY_executed").exists());
    redacted(&output, &f);
}
#[test]
fn invalid_selectors_fail_before_io() {
    for args in [
        vec!["inspect"],
        vec!["inspect", "--pid", "0"],
        vec!["scan", "--pid", "4294967296"],
        vec!["scan", "--pid", "-1"],
        vec!["inspect", "--pid", "1", "--pid", "2"],
        vec![
            "inspect",
            "--module",
            "/PRIVATE_CANARY_missing",
            "--pid",
            "1",
        ],
        vec!["inspect", "--module", "/PRIVATE_CANARY_missing", "--watch"],
        vec!["scan", "--cgroup", "PRIVATE_CANARY_value"],
        vec!["scan", "--pid"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_CANARY"));
    }
}
#[test]
fn partial_scan_keeps_valid_pid() {
    let f = Fixture::new();
    let module = f.module();
    let child = f.child(&module);
    let output = cli(&[
        "scan",
        "--pid",
        &child.0.id().to_string(),
        "--pid",
        "2147483647",
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let doc = json(&output);
    assert!(
        doc["processes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["pid"] == child.0.id())
    );
    assert!(
        doc["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["pid"] == 2147483647u32)
    );
}
#[test]
fn inventory_never_claims_execution() {
    let f = Fixture::new();
    let module = f.module();
    let child = f.child(&module);
    for args in [
        vec!["inspect", "--module", module.to_str().unwrap(), "--json"],
        vec!["inspect", "--pid", &child.0.id().to_string(), "--json"],
    ] {
        let output = cli(&args);
        let doc = json(&output);
        assert_eq!(doc["capabilities"]["execution"], "not_observed");
        assert_eq!(doc["capabilities"]["provider_activation"], "unknown");
        assert_eq!(doc["capabilities"]["provider_interfaces"], "unknown");
        assert!(doc.get("policy").is_none());
        assert!(doc.get("cbom").is_none());
    }
    let output = cli(&["inspect", "--module", module.to_str().unwrap()]);
    let human = String::from_utf8(output.stdout).unwrap();
    assert!(human.contains("do not prove activation or execution"));
}
#[test]
fn independent_modules_survive_unavailable_inputs() {
    let f = Fixture::new();
    let module = f.module();
    let missing = f.0.join("PRIVATE_CANARY_missing");
    let output = cli(&[
        "inspect",
        "--module",
        missing.to_str().unwrap(),
        "--module",
        module.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let doc = json(&output);
    assert_eq!(doc["modules"].as_array().unwrap().len(), 1);
    assert_eq!(doc["errors"][0]["reason"], "unavailable");
    redacted(&output, &f);
    let output = cli(&["inspect", "--module", missing.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(4));
    redacted(&output, &f);
    assert_eq!(
        cli(&["inspect", "--pid", "2147483647", "--json"])
            .status
            .code(),
        Some(4)
    );
}
#[test]
fn output_failure_is_exit_one() {
    let f = Fixture::new();
    let module = f.module();
    let output = Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(["inspect", "--module", module.to_str().unwrap(), "--json"])
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    redacted(&output, &f);
}
#[test]
fn discovery_help_is_supported() {
    for command in ["scan", "inspect"] {
        assert_eq!(cli(&[command, "--help"]).status.code(), Some(0));
    }
}

fn digest(path: &std::path::Path) -> String {
    Sha256::digest(fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
