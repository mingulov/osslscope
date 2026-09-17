//! CLI dispatch (P1-0 skeleton). Full contract: PRD §6; exit-code
//! taxonomy 0/1/2/3/4/10(+11) lands with `check` at P3.
use std::process::ExitCode;

pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    let argv: Vec<String> = args.collect();
    let cmd = argv.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "doctor" => crate::doctor::run(&argv[1..]),
        "inspect" => crate::inspect::run(&argv[1..]),
        "alias-audit" => crate::aliases::run(&argv[1..]),
        "report" => crate::doctor::unimplemented("report"),
        "check" => crate::doctor::unimplemented("check"),
        "help" | "--help" | "-h" => {
            println!("osslscope — non-interposing OpenSSL observer");
            println!("usage: osslscope <doctor|inspect|alias-audit> [args]");
            println!("  doctor       preflight: kernel, caps, LSM, target suitability");
            println!("  inspect      dispatch inventory of a live --pid target");
            println!("  alias-audit  group a harvest doc's rows by shared address");
            println!("planned: report, check (policy gates land next)");
            ExitCode::SUCCESS
        }
        "--version" | "-V" => {
            println!("osslscope {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("osslscope: unknown subcommand '{other}' (see: osslscope help)");
            ExitCode::from(2)
        }
    }
}
