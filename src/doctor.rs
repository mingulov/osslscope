//! `doctor` preflight (P1 exit 5 owns the rule set; P1-0 skeleton).
use std::process::ExitCode;

/// Shared "not yet implemented" exit for later-phase subcommands.
pub fn unimplemented(cmd: &str) -> ExitCode {
    eprintln!("osslscope {cmd}: not yet implemented (see PLAN phase gates)");
    ExitCode::from(4)
}

pub fn run(_args: &[String]) -> ExitCode {
    unimplemented("doctor")
}
