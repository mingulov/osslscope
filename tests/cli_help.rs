// SPDX-License-Identifier: GPL-3.0-or-later
//! G4 U3/U5: top-level help and help-dispatch pins (binary stdout
//! capture; `cli::run` prints, so only the binary shows the bytes).
use std::process::{Command, Output};

fn bin(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_osslscope"))
        .args(args)
        .output()
        .unwrap()
}

/// G4 U3a: scan/inspect are first-class bullets (not footer-only);
/// top help keeps its ~1825B brevity and gains no flags.
#[test]
fn g4_u3a_top_help_surfaces_scan_and_inspect() {
    let output = bin(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("  scan         passive process/module discovery"),
        "scan is a first-class bullet:\n{text}"
    );
    assert!(
        text.contains("  inspect      passive per-target detail"),
        "inspect is a first-class bullet:\n{text}"
    );
    assert!(
        !text.contains("scan/inspect  passive"),
        "footer form retired:\n{text}"
    );
    assert!(
        text.contains(
            "usage: osslscope <scan|inspect|doctor|report|check|alias-audit|service|export|watch> [args]"
        ),
        "no new flags/verbs in the synopsis:\n{text}"
    );
    assert!(
        output.stdout.len() < 2000,
        "brevity kept, got {} bytes",
        output.stdout.len()
    );
}

/// G4 U3b: `help <sub>` honors its argument (byte-identical to
/// `<sub> --help`); `version` is a verb alias for `--version`.
#[test]
fn g4_u3b_help_honors_subcommand_and_version_verb() {
    for sub in ["scan", "report", "service", "export", "watch"] {
        let via_help = bin(&["help", sub]);
        let direct = bin(&[sub, "--help"]);
        assert_eq!(via_help.status.code(), Some(0), "help {sub}");
        assert!(direct.status.code() == Some(0), "{sub} --help stays exit 0");
        assert_eq!(via_help.stdout, direct.stdout, "help {sub} == {sub} --help");
    }
    let version = bin(&["version"]);
    let flag = bin(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(version.stderr.is_empty());
    assert_eq!(
        version.stdout, flag.stdout,
        "version verb == --version flag"
    );
    let bad = bin(&["help", "frobnicate"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("unknown subcommand 'frobnicate'"),
        "unknown help topic stays a usage error: {}",
        String::from_utf8_lossy(&bad.stderr)
    );
}

/// G4 U5/S1: every live-observation `--help` carries the attach
/// warning (privileged, system-wide, finite window).
#[test]
fn g4_u5_help_texts_carry_the_attach_warning() {
    let cases: &[(&[&str], &str)] = &[
        (&["report", "--help"], "report"),
        (&["check", "--help"], "check"),
        (
            &["scan", "--observe-providers", "--help"],
            "observe-providers",
        ),
        (
            &["scan", "--watch", "--observe-crypto", "--help"],
            "observe-crypto",
        ),
        (&["service", "--help"], "service"),
        (&["export", "--help"], "export"),
        (&["watch", "--help"], "watch"),
    ];
    for (args, name) in cases {
        let output = bin(args);
        assert_eq!(output.status.code(), Some(0), "{name} --help");
        let text = String::from_utf8_lossy(&output.stdout);
        for needle in ["privileged", "system-wide", "finite"] {
            assert!(
                text.contains(needle),
                "{name} --help lacks '{needle}':\n{text}"
            );
        }
    }
}
