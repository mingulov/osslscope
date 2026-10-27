// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent physical-entry stimulus controls. These tests load no BPF and
//! do not qualify the observer; privileged installed acceptance uses this same
//! fixture and its application-owned counter as the independent oracle.
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static SEQ: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osslscope-count-fixture-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        for (source, output, flags) in [
            ("provider_observation.c", "app", vec!["-O2"]),
            (
                "provider_observation_provider.c",
                "provider.so",
                vec!["-O2", "-shared", "-fPIC"],
            ),
        ] {
            let mut cc = Command::new("cc");
            cc.args(flags)
                .args(["-Wall", "-Wextra", "-Werror"])
                .arg(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures")
                        .join(source),
                )
                .arg("-o")
                .arg(path.join(output));
            if output == "app" {
                cc.args(["-lcrypto", "-ldl"]);
            }
            let result = cc.output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        Self(path)
    }
    fn run(&self, input: &str) -> (i32, String) {
        let mut child = Command::new(self.0.join("app"))
            .arg(self.0.join("provider.so"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        (
            result.status.code().unwrap(),
            String::from_utf8(result.stdout).unwrap(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn advertisements_do_not_call_and_shared_callbacks_survive_unquery_as_controls() {
    let fixture = Fixture::new();
    let (status, output) =
        fixture.run("P\nI\nQ\nQ\nR\nC 37\nR\nU\nB 5\nR\nZ\nV\nQ\nU\nC 3\nR\nE\n");
    assert_eq!(status, 0, "{output}");
    let counters: Vec<_> = output
        .lines()
        .filter(|l| l.starts_with("counter "))
        .collect();
    assert_eq!(
        counters,
        [
            "counter 0",
            "counter 37",
            "counter 42",
            "counter 0",
            "counter 3"
        ]
    );
    assert!(output.contains("calls C 37 37\n"));
    assert!(output.contains("calls B 5 42\n"));
    assert!(output.contains("ack Q 1 1 0 2 1 0\n"));
}

#[test]
fn default_conflict_control_and_bounded_call_input_remain_separate() {
    let fixture = Fixture::new();
    let (status, output) = fixture.run("I\nQ\nU\nV\nS\nH\nF\nX\nE\n");
    assert_eq!(status, 0, "{output}");
    assert!(output.contains("ack X 1 1 1 1 1 1\n"));
    let (status, output) = fixture.run("P\nC 37\nR\nE\n");
    assert_eq!(status, 0, "{output}");
    assert!(output.contains("ack C 0 0 0 0 0 0\n"));
    assert!(output.contains("counter 0\n"));
    for count in [
        "-1",
        "1000001",
        "37junk",
        "",
        "999999999999999999999999999999999999999999999999999999999999999999999999",
    ] {
        let (status, output) = fixture.run(&format!("P\nI\nQ\nC {count}\n"));
        assert_eq!(status, 7, "accepted invalid count {count}: {output}");
        assert!(!output.contains("calls C"));
    }
}
