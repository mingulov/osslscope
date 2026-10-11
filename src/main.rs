//! SPDX-License-Identifier: GPL-3.0-or-later
//! osslscope CLI entry. Subcommand set mirrors p11scope
//! (`doctor/inspect/report/check`); argument-parsing crate chosen in P1
//! (positional parsing until then — PLAN §3 YAGNI).
use std::process::ExitCode;

fn main() -> ExitCode {
    // std::env::args() panics on non-UTF8 argv (exit 101). F-G/Bm2:
    // non-UTF-8 argv is rejected here with exit 2 (usage error,
    // before any side effect) — lossy conversion would silently
    // EXECUTE different target bytes than the operator typed. The
    // offending bytes are never echoed (R07).
    let os_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let argv = match osslscope::args::decode_argv(&os_args) {
        Ok(argv) => argv,
        Err(e) => {
            eprintln!("osslscope: {e}");
            return ExitCode::from(2);
        }
    };
    osslscope::cli::run(argv.into_iter())
}
