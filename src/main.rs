//! osslscope CLI entry. Subcommand set mirrors p11scope
//! (`doctor/inspect/report/check`); argument-parsing crate chosen in P1
//! (positional parsing until then — PLAN §3 YAGNI).
use std::process::ExitCode;

fn main() -> ExitCode {
    osslscope::cli::run(std::env::args().skip(1))
}
