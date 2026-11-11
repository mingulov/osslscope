// SPDX-License-Identifier: GPL-3.0-or-later
//! Docker-attach signal leg: first SIGINT through the docker signal
//! path still yields ack + end record + exit 3. Gated: needs docker
//! plus the ci-repro image plus OSSL_DOCKER_TESTS=1. The docker
//! client's `got 3 SIGTERM/SIGINTs` line is client chatter (proven
//! in gaps §8.1 W4) and is never asserted here.

use std::process::Command;
use std::time::{Duration, Instant};

fn gated() -> bool {
    std::env::var("OSSL_DOCKER_TESTS").as_deref() == Ok("1")
        && Command::new("docker").arg("--version").output().is_ok()
}

#[test]
#[ignore]
fn v060_docker_attach_first_sigint_acks_and_exits_3() {
    if !gated() {
        eprintln!("skip: set OSSL_DOCKER_TESTS=1 with docker + ci-repro:latest");
        return;
    }
    // The observer is the freshly built host binary, volume-mounted as
    // container PID 1; the workload is a second process via exec. The
    // ci-repro image only needs a compatible glibc + python3. (On panic
    // the container leaks; clean with `docker rm -f ossl-sig-<pid>`.)
    let bin = env!("CARGO_BIN_EXE_osslscope");
    let name = format!("ossl-sig-{}", std::process::id());
    let run = Command::new("docker")
        .args(["run", "-d", "--name", &name])
        .arg(format!("-v{bin}:/osslscope:ro"))
        .args(["--entrypoint", "/osslscope", "ci-repro:latest"])
        .args(["scan", "--watch", "--interval", "1", "--duration", "120"])
        .output()
        .unwrap();
    if !run.status.success() {
        eprintln!("skip: observer container failed to start (image/glibc mismatch)");
        return;
    }
    let workload = Command::new("docker")
        .args([
            "exec",
            "-d",
            &name,
            "python3",
            "-c",
            "import ssl, time; time.sleep(900)",
        ])
        .output()
        .unwrap();
    if !workload.status.success() {
        eprintln!("skip: workload exec failed in image");
        let _ = Command::new("docker").args(["rm", "-f", &name]).output();
        return;
    }
    std::thread::sleep(Duration::from_millis(3000));
    let started = Instant::now();
    let kill = Command::new("docker")
        .args(["kill", "--signal=INT", &name])
        .output()
        .unwrap();
    assert!(kill.status.success());
    let elapsed = started.elapsed();
    std::thread::sleep(Duration::from_millis(1500));
    let logs = Command::new("docker")
        .args(["logs", &name])
        .output()
        .unwrap();
    let inspect = Command::new("docker")
        .args(["inspect", "-f", "{{.State.ExitCode}}", &name])
        .output()
        .unwrap();
    let _ = Command::new("docker").args(["rm", "-f", &name]).output();
    assert!(
        elapsed < Duration::from_secs(5),
        "slow shutdown: {elapsed:?}"
    );
    let text =
        String::from_utf8_lossy(&logs.stdout).to_string() + &String::from_utf8_lossy(&logs.stderr);
    assert!(text.contains("shutting down"), "no ack: {text}");
    assert!(text.contains("Watch ended"), "no end record: {text}");
    assert_eq!(String::from_utf8_lossy(&inspect.stdout).trim(), "3");
}
