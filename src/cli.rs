//! SPDX-License-Identifier: GPL-3.0-or-later
//! CLI dispatch (P1-0 skeleton). Full contract: PRD §6; exit-code
//! taxonomy 0/1/2/3/4/10 (see usage.md).
use std::process::ExitCode;

/// One help line per exit code (mirrors docs/usage.md#exit-codes).
/// Exits 3/4 additionally print their single stderr reason at runtime
/// (see `report::exit_reason_line`).
pub(crate) fn exit_code_help() -> [&'static str; 7] {
    [
        "  exit 0: ok (help or successful controls; no complete-execution claim)",
        "  exit 1: child, artifact-delivery, or usable runtime failure",
        "  exit 2: invalid arguments, policy, or explicit companion",
        "  exit 3: PARTIAL report or unavailable/denied capability",
        "  exit 4: setup/environment refusal without usable observation (no verdict)",
        "  exit 10: definite policy violation (takes precedence)",
        "  exit 11: policy inconclusive (Unknown-only evidence)",
    ]
}

pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    let argv: Vec<String> = args.collect();
    let cmd = argv.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "doctor" if argv[1..].iter().any(|arg| arg == "--discovery") => {
            crate::doctor::discovery(&argv[1..])
        }
        "doctor" if argv[1..].iter().any(|arg| arg == "--libcrypto") => {
            crate::doctor::profiled::run(&argv[1..])
        }
        // Sectioned preflight: any sectioned-only selector or object
        // override. (--discovery/--libcrypto guards above win; combining
        // --libcrypto with these is a usage error inside profiled::run.)
        // Bare --count-object/--observation-object stay on the focused
        // self-controls below (explicit-companion override path).
        "doctor"
            if argv[1..].iter().any(|arg| {
                matches!(
                    arg.as_str(),
                    "--pid"
                        | "--exe"
                        | "--object"
                        | "--members-object"
                        | "--table"
                        | "--force-offset"
                        | "--provider-table"
                )
            }) =>
        {
            crate::doctor::run(&argv[1..])
        }
        "doctor" => crate::doctor::focused::run(&argv[1..]),
        "scan" | "inspect" if argv[1..].iter().any(|arg| arg == "--observe-crypto") => {
            crate::crypto_watch::run(&argv)
        }
        "scan" | "inspect" if argv[1..].iter().any(|arg| arg == "--observe-providers") => {
            crate::provider_observation::cli::run(&argv)
        }
        "scan" | "inspect" => crate::inventory::cli::run(cmd, &argv[1..]),
        "alias-audit" => crate::aliases::run(&argv[1..]),
        "report" => crate::report::run(&argv[1..]),
        "check" => crate::check::run(&argv[1..]),
        "help" | "--help" | "-h" => {
            println!("osslscope — non-interposing OpenSSL observer");
            println!("usage: osslscope <scan|inspect|doctor|report|check|alias-audit> [args]");
            println!(
                "  doctor       inventory, companion integrity and functional tracing preflight"
            );
            println!(
                "  report       observe learned callbacks in one selected PID or foreground run"
            );
            println!("  check        policy gate over a window (CI use; exits 10 on violation)");
            println!("  alias-audit  group a harvest doc's rows by shared address");
            println!(
                "  report/check use --pid PID or run -- COMMAND; --libcrypto selects legacy diagnostics"
            );
            println!(
                "  scan/inspect  passive process/module discovery; no profile or BPF required"
            );
            println!(
                "  scan --watch --observe-crypto  observe discovered scope members separately"
            );
            println!("  --observe-providers  public provider API observation (default 30 seconds)");
            println!("  doctor --discovery  capability checks without a build catalogue");
            println!(
                "  doctor --pid PID | --exe PATH  environment + foreign-backing/target preflight"
            );
            println!(
                "  doctor --object O --count-object C --members-object M  admitted preflight with explicit objects"
            );
            println!("  discovery does not prove provider activation or execution");
            for line in exit_code_help() {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        "--version" | "-V" => {
            println!("osslscope {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        other => {
            crate::report::err_line(&format!(
                "osslscope: unknown subcommand '{other}' (see: osslscope help)"
            ));
            ExitCode::from(2)
        }
    }
}

/// A parsed and fully admitted command. Preparation performs no acquisition.
pub enum PreparedCommand {
    Immediate(std::process::ExitCode),
    Report(crate::report::Prepared),
    Check(crate::check::Prepared),
}
impl PreparedCommand {
    /// Parsed normal/legacy routing; workload argv never participates.
    pub fn is_focused(&self) -> bool {
        match self {
            Self::Report(p) => p.is_focused(),
            Self::Check(p) => p.is_focused(),
            Self::Immediate(_) => false,
        }
    }
    pub fn setup_deadline(&self) -> Option<std::time::Instant> {
        match self {
            Self::Report(p) => p.setup_deadline(),
            Self::Check(p) => p.setup_deadline(),
            Self::Immediate(_) => None,
        }
    }
    pub fn workload_fd(&self) -> std::io::Result<Option<std::os::fd::BorrowedFd<'_>>> {
        match self {
            Self::Report(p) => p.workload_fd(),
            Self::Check(p) => p.workload_fd(),
            Self::Immediate(_) => Ok(None),
        }
    }
    pub fn execute(self) -> Result<crate::report::CaptureCommandResult, std::process::ExitCode> {
        match self {
            Self::Report(p) => Ok(p.execute()),
            Self::Check(p) => Ok(p.execute()),
            Self::Immediate(code) => Err(code),
        }
    }
}
pub fn prepare(args: impl Iterator<Item = String>) -> PreparedCommand {
    let argv: Vec<_> = args.collect();
    match argv.first().map(String::as_str) {
        Some("report") => match crate::report::prepare(&argv[1..]) {
            Ok(p) => PreparedCommand::Report(p),
            Err(e) => PreparedCommand::Immediate(e),
        },
        Some("check") => match crate::check::prepare(&argv[1..]) {
            Ok(p) => PreparedCommand::Check(p),
            Err(e) => PreparedCommand::Immediate(e),
        },
        _ => PreparedCommand::Immediate(run(argv.into_iter())),
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;
    #[test]
    fn inventory_help_is_supported() {
        let args = ["inspect", "--help"].map(String::from);
        assert!(
            matches!(prepare(args.into_iter()), PreparedCommand::Immediate(code) if code == ExitCode::SUCCESS)
        );
    }

    #[test]
    fn help_exit_block_names_every_code_once() {
        // P1-help/exit: the top-level help carries one line per exit
        // code, mirroring docs/usage.md#exit-codes.
        let lines = exit_code_help();
        assert_eq!(lines.len(), 7);
        let joined = lines.join("\n");
        for code in ["0", "1", "2", "3", "4", "10", "11"] {
            assert_eq!(
                joined.matches(&format!("exit {code}:")).count(),
                1,
                "{joined}"
            );
        }
        assert!(joined.contains("no verdict"), "{joined}");
        assert!(joined.contains("violation"), "{joined}");
    }
}
