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

/// First-run pointer for top-level help (printed after the exit
/// lines): one shared sentence, not per-command tutorials.
pub(crate) fn blocked_pointer_top() -> &'static str {
    "  blocked? run 'osslscope doctor' first; '<cmd> --help' names that command's exits"
}

/// First-run pointer for subcommand helps (printed after the exit
/// lines): the doctor command diagnoses; help texts do not.
pub(crate) fn blocked_pointer_sub() -> &'static str {
    "  first run blocked? 'osslscope doctor' diagnoses capabilities (CAP_BPF+CAP_PERFMON; same uid or root for foreign targets)"
}

/// Tokens in flag position: a value-taking option consumes the next
/// token (whatever it is — even a flag-shaped pathname), so option
/// VALUES never select a dispatch route. `value_flags` must be built
/// from the dispatched parsers' VALUE_OPTIONS lists (never a
/// hand-mirror); a missing entry reintroduces value-confusion for
/// that option (misroute on flag-shaped values instead of honest
/// parsing).
fn flags_in_position<'a>(args: &'a [String], value_flags: &[&str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        out.push(a);
        i += if value_flags.contains(&a) { 2 } else { 1 };
    }
    out
}

/// Doctor dispatch route (precedence: discovery > profiled >
/// sectioned > focused).
#[derive(Debug, PartialEq, Eq)]
enum DoctorRoute {
    Discovery,
    Profiled,
    Sectioned,
    Focused,
}

fn doctor_route(args: &[String]) -> DoctorRoute {
    // Built from the parsers' own VALUE_OPTIONS (sectioned, focused,
    // profiled, discovery): the router cannot drift from the parsers
    // — a new value-taking match arm extends its parser's list, and
    // the router follows. Duplicates across parsers are harmless
    // (membership test only).
    let value_flags: Vec<&str> = crate::doctor::SECTIONED_VALUE_OPTIONS
        .iter()
        .chain(crate::doctor::focused::VALUE_OPTIONS)
        .chain(crate::doctor::profiled::VALUE_OPTIONS)
        .chain(crate::doctor::DISCOVERY_VALUE_OPTIONS)
        .copied()
        .collect();
    // Sectioned-only selectors/overrides.
    const SECTIONED: &[&str] = &[
        "--pid",
        "--exe",
        "--object",
        "--members-object",
        "--table",
        "--force-offset",
        "--provider-table",
    ];
    let flags = flags_in_position(args, &value_flags);
    if flags.contains(&"--discovery") {
        DoctorRoute::Discovery
    } else if flags.contains(&"--libcrypto") {
        // Combining --libcrypto with sectioned flags is a usage
        // error inside profiled::run (pinned by its tests).
        DoctorRoute::Profiled
    } else if SECTIONED.iter().any(|f| flags.contains(f)) {
        DoctorRoute::Sectioned
    } else {
        // Bare --count-object/--observation-object stay on the
        // focused self-controls (explicit-companion override path).
        DoctorRoute::Focused
    }
}

/// Scan/inspect dispatch route (precedence: crypto > providers >
/// inventory — the historical guard order).
#[derive(Debug, PartialEq, Eq)]
enum ScanRoute {
    CryptoWatch,
    Providers,
    Inventory,
}

fn scan_route(args: &[String]) -> ScanRoute {
    // Built from the parsers' own VALUE_OPTIONS (inventory,
    // provider_observation — crypto_watch takes none beyond its bare
    // selector): the router cannot drift from the parsers.
    let value_flags: Vec<&str> = crate::inventory::cli::VALUE_OPTIONS
        .iter()
        .chain(crate::provider_observation::cli::VALUE_OPTIONS)
        .copied()
        .collect();
    let flags = flags_in_position(args, &value_flags);
    if flags.contains(&"--observe-crypto") {
        ScanRoute::CryptoWatch
    } else if flags.contains(&"--observe-providers") {
        ScanRoute::Providers
    } else {
        ScanRoute::Inventory
    }
}

pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    let argv: Vec<String> = args.collect();
    let cmd = argv.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "doctor" => match doctor_route(&argv[1..]) {
            DoctorRoute::Discovery => crate::doctor::discovery(&argv[1..]),
            DoctorRoute::Profiled => crate::doctor::profiled::run(&argv[1..]),
            DoctorRoute::Sectioned => crate::doctor::run(&argv[1..]),
            DoctorRoute::Focused => crate::doctor::focused::run(&argv[1..]),
        },
        "scan" | "inspect" => match scan_route(&argv[1..]) {
            ScanRoute::CryptoWatch => crate::crypto_watch::run(&argv),
            ScanRoute::Providers => crate::provider_observation::cli::run(&argv),
            ScanRoute::Inventory => crate::inventory::cli::run(cmd, &argv[1..]),
        },
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
            println!("{}", blocked_pointer_top());
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
    fn doctor_route_consumes_values_before_routing() {
        fn route(words: &[&str]) -> DoctorRoute {
            doctor_route(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>())
        }
        // Plain routes.
        assert_eq!(route(&[]), DoctorRoute::Focused);
        assert_eq!(route(&["--json"]), DoctorRoute::Focused);
        assert_eq!(route(&["--count-object", "c.o"]), DoctorRoute::Focused);
        assert_eq!(
            route(&["--observation-object", "o.o", "--count-object", "c.o"]),
            DoctorRoute::Focused
        );
        assert_eq!(route(&["--discovery"]), DoctorRoute::Discovery);
        assert_eq!(route(&["--libcrypto", "lib"]), DoctorRoute::Profiled);
        assert_eq!(route(&["--pid", "1"]), DoctorRoute::Sectioned);
        assert_eq!(route(&["--exe", "x"]), DoctorRoute::Sectioned);
        assert_eq!(
            route(&[
                "--object",
                "h",
                "--count-object",
                "c",
                "--members-object",
                "m"
            ]),
            DoctorRoute::Sectioned
        );
        // Precedence: discovery > profiled > sectioned.
        assert_eq!(
            route(&["--discovery", "--pid", "1"]),
            DoctorRoute::Discovery
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--pid", "1"]),
            DoctorRoute::Profiled
        );
        // Flag-shaped VALUES never route: a companion file literally
        // named --pid/--discovery/--libcrypto stays a focused value.
        assert_eq!(
            route(&["--observation-object", "--pid", "--count-object", "c.o"]),
            DoctorRoute::Focused
        );
        assert_eq!(
            route(&["--observation-object", "--discovery"]),
            DoctorRoute::Focused
        );
        assert_eq!(
            route(&["--count-object", "--libcrypto"]),
            DoctorRoute::Focused
        );
        assert_eq!(route(&["--format", "--pid"]), DoctorRoute::Focused);
        // ... while a real flag after a consumed value still routes.
        assert_eq!(
            route(&["--observation-object", "--pid", "--exe", "x"]),
            DoctorRoute::Sectioned
        );
        // Truncated invocations route by the flag in position (the
        // subcommand reports the missing value, exit 2, as before).
        assert_eq!(route(&["--pid"]), DoctorRoute::Sectioned);
        assert_eq!(route(&["--observation-object"]), DoctorRoute::Focused);
        // --flag=value is not a flag in any sub-parser (all reject
        // it): routing matches the naive-guard behavior exactly.
        assert_eq!(route(&["--pid=1"]), DoctorRoute::Focused);
    }

    #[test]
    fn scan_route_consumes_values_before_routing() {
        fn route(words: &[&str]) -> ScanRoute {
            scan_route(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>())
        }
        assert_eq!(route(&[]), ScanRoute::Inventory);
        assert_eq!(route(&["--pid", "1"]), ScanRoute::Inventory);
        assert_eq!(route(&["--watch"]), ScanRoute::Inventory);
        assert_eq!(route(&["--observe-crypto"]), ScanRoute::CryptoWatch);
        assert_eq!(route(&["--observe-providers"]), ScanRoute::Providers);
        // Precedence is the historical guard order.
        assert_eq!(
            route(&["--observe-crypto", "--observe-providers"]),
            ScanRoute::CryptoWatch
        );
        // Flag-shaped values never route.
        assert_eq!(
            route(&["--module", "--observe-crypto"]),
            ScanRoute::Inventory
        );
        assert_eq!(
            route(&["--pid", "--observe-providers"]),
            ScanRoute::Inventory
        );
        assert_eq!(
            route(&["--cgroup", "--observe-crypto", "--watch"]),
            ScanRoute::Inventory
        );
        // ... while a real flag after a consumed value still routes.
        assert_eq!(
            route(&["--module", "--observe-crypto", "--observe-providers"]),
            ScanRoute::Providers
        );
        assert_eq!(
            route(&["--observe-crypto", "--module", "m"]),
            ScanRoute::CryptoWatch
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
