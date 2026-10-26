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
    let Some(deadline) = prepared.setup_deadline() else {
        osslscope::report::err_line("osslscope: setup deadline overflow");
        return ExitCode::from(2);
    };
    let workload = match prepared.workload_fd() {
        Ok(fd) => fd,
        Err(e) => {
            osslscope::report::err_line(&format!("osslscope: workload fd: {e}"));
            return ExitCode::from(4);
        }
    };
    // SAFETY: main has parsed/admitted only; no worker, target, or native acquisition.
    let runtime = match unsafe {
        osslscope::lifecycle_producer::LifecycleRuntime::bootstrap_early(deadline, workload)
    } {
        Ok(r) => r,
        Err(e) => {
            osslscope::report::err_line(&e.to_string());
            return ExitCode::from(4);
        }
    };
    std::panic::set_hook(Box::new(|_| {
        osslscope::report::err_line("osslscope: capture panicked")
    }));
    let installed = runtime.install();
    let execution = match installed {
        Ok(_guard) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepared.execute())),
        Err(e) => {
            osslscope::report::err_line(&e.to_string());
            Ok(Err(ExitCode::from(4)))
        }
    };
    let start = std::time::Instant::now();
    let deadline = start
        .checked_add(std::time::Duration::from_secs(2))
        .unwrap_or(start);
    let receipt = runtime.shutdown(deadline);
    match execution {
        Ok(Ok(mut result)) => {
            osslscope::report::apply_producer_shutdown(
                &mut result,
                &receipt,
                &mut std::io::stderr(),
            );
            ExitCode::from(result.exit_code)
        }
        Ok(Err(code)) => {
            if receipt.state != osslscope::lifecycle_producer::ProducerShutdownState::Complete {
                osslscope::report::err_line("lifecycle producer cleanup unresolved");
            }
            code
        }
        Err(_) => {
            osslscope::report::err_line("osslscope: capture unwound");
            if receipt.state != osslscope::lifecycle_producer::ProducerShutdownState::Complete {
                osslscope::report::err_line("lifecycle producer cleanup unresolved");
            }
            ExitCode::from(1)
        }
    }
}
