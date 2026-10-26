// SPDX-License-Identifier: GPL-3.0-or-later
//! The source-build entrypoint must not attribute an archive to a parent repo.
use std::path::Path;
use std::process::{Command, Output};

fn git(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=build-script-test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn preflight(dir: &Path) -> String {
    let output = Command::new("sh")
        .arg("scripts/build-dev.sh")
        .args(["--host-only", "--check-only", "--offline"])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "preflight: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn archive_does_not_inherit_parent_git_identity() {
    let dir = std::env::temp_dir().join(format!(
        "osslscope-build-identity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    git(&dir, &["init", "--quiet"]);
    git(
        &dir,
        &["commit", "--quiet", "--allow-empty", "-m", "parent fixture"],
    );
    let archive = dir.join("archive");
    std::fs::create_dir_all(archive.join("scripts")).unwrap();
    std::fs::create_dir(archive.join("src")).unwrap();
    std::fs::write(
        archive.join("Cargo.toml"),
        "[package]\nname='build-identity-fixture'\nversion='0.0.0'\nedition='2021'\n",
    )
    .unwrap();
    std::fs::write(archive.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build-dev.sh"),
        archive.join("scripts/build-dev.sh"),
    )
    .unwrap();
    let archive_output = preflight(&archive);
    git(&archive, &["init", "--quiet"]);
    git(
        &archive,
        &["add", "Cargo.toml", "src/main.rs", "scripts/build-dev.sh"],
    );
    git(&archive, &["commit", "--quiet", "-m", "product fixture"]);
    let revision =
        String::from_utf8(git(&archive, &["rev-parse", "--short", "HEAD"]).stdout).unwrap();
    let checkout_output = preflight(&archive);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        archive_output.contains("product: unknown (dirty=unknown)"),
        "archive inherited a parent revision: {archive_output}"
    );
    assert!(
        checkout_output.contains(&format!("product: {} ", revision.trim())),
        "own checkout lost its revision: {checkout_output}"
    );
}
