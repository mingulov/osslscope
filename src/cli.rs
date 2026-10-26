//! SPDX-License-Identifier: GPL-3.0-or-later
//! CLI dispatch (P1-0 skeleton). Full contract: PRD §6; exit-code
//! taxonomy 0/1/2/3/4/10 (see usage.md).
use std::process::ExitCode;

pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    let argv: Vec<String> = args.collect();
    let cmd = argv.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "doctor" => crate::doctor::profiled::run(&argv[1..]),
        "inspect" => {
            crate::report::err_line(
                "osslscope inspect: deferred beyond v0.2; use report --libcrypto PATH run -- COMMAND",
            );
            ExitCode::from(2)
        }
        "alias-audit" => crate::aliases::run(&argv[1..]),
        "report" => crate::report::run(&argv[1..]),
        "check" => crate::check::run(&argv[1..]),
        "help" | "--help" | "-h" => {
            println!("osslscope — non-interposing OpenSSL observer");
            println!("usage: osslscope <doctor|report|check|alias-audit> [args]");
            println!(
                "  doctor       preflight for one exact library/kernel profile and Count object"
            );
            println!("  report       count enrolled callbacks in an owned foreground run");
            println!("  check        policy gate over a window (CI use; exits 10 on violation)");
            println!("  alias-audit  group a harvest doc's rows by shared address");
            println!(
                "  report/check require --libcrypto PATH and run -- COMMAND; coverage is PARTIAL"
            );
            println!("  live inspect, foreign PID and dynamic providers are deferred beyond v0.2");
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
    fn live_inspect_is_explicitly_deferred() {
        let args = ["inspect", "--help"].map(String::from);
        assert!(
            matches!(prepare(args.into_iter()), PreparedCommand::Immediate(code) if code == ExitCode::from(2))
        );
    }
}
