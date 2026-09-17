//! CLI dispatch (P1-0 skeleton). Full contract: PRD §6; exit-code
//! taxonomy 0/1/2/3/4/10(+11) lands with `check` at P3.
use std::process::ExitCode;

pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    let argv: Vec<String> = args.collect();
    let cmd = argv.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "doctor" => crate::doctor::run(&argv[1..]),
        "inspect" => crate::inspect::run(&argv[1..]),
        "report" => crate::doctor::unimplemented("report"),
        "check" => crate::doctor::unimplemented("check"),
        "help" | "--help" | "-h" => {
            println!("osslscope — non-interposing OpenSSL observer");
            println!("usage: osslscope <doctor|inspect|report|check> [args]");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("osslscope: unknown subcommand '{other}' (see: osslscope help)");
            ExitCode::from(2)
        }
    }
}
