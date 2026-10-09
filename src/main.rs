//! SPDX-License-Identifier: GPL-3.0-or-later
//! osslscope CLI entry. Subcommand set mirrors p11scope
//! (`doctor/inspect/report/check`); argument-parsing crate chosen in P1
//! (positional parsing until then — PLAN §3 YAGNI).
use std::process::ExitCode;

fn main() -> ExitCode {
    // T04 (coordinator review; beyond the listed T04 files — approve or
    // revert): std::env::args() panics on non-UTF8 argv (exit 101). Lossy
    // conversion keeps operator/target bytes out of panics (R07/R08);
    // parsing still rejects anything invalid with exit 2.
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    osslscope::cli::run(argv.into_iter())
}
