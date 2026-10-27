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
            osslscope::report::err_line(&format!("osslscope: {e}"));
            return ExitCode::from(2);
        }
    };
    let prepared = osslscope::cli::prepare(argv.into_iter());
    if let osslscope::cli::PreparedCommand::Immediate(code) = prepared {
        return code;
    }
    if prepared.setup_deadline().is_none() {
        osslscope::report::err_line("osslscope: setup deadline overflow");
        return ExitCode::from(2);
    }
    if let Err(error) = prepared.workload_fd() {
        osslscope::report::err_line(&format!("osslscope: workload fd: {error}"));
        return ExitCode::from(4);
    }
    // Focused and explicit legacy runs acquire stopped-child custody before
    // BPF resources. The synchronous controller owns discovery and teardown.
    std::panic::set_hook(Box::new(|_| {
        osslscope::report::err_line("osslscope: capture panicked")
    }));
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepared.execute())) {
        Ok(Ok(result)) => ExitCode::from(result.exit_code),
        Ok(Err(code)) => code,
        Err(_) => {
            osslscope::report::err_line("osslscope: capture unwound");
            ExitCode::from(1)
        }
    }
}
