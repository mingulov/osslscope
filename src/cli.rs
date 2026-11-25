//! SPDX-License-Identifier: GPL-3.0-or-later
//! CLI dispatch (P1-0 skeleton). Full contract: PRD §6; exit-code
//! taxonomy 0/1/2/3/4/10 (see usage.md).
use std::process::ExitCode;

/// Exit-code lines for observation surfaces (scan/inspect
/// provider observation): policy verdicts 10/11 are unemittable
/// here, and interruption lands on exit 3 — see
/// docs/provider-observation.md.
pub(crate) fn exit_code_help_observation() -> [&'static str; 5] {
    [
        "  exit 0: completed inventory/observation",
        "  exit 1: internal or output failure",
        "  exit 2: invalid arguments",
        "  exit 3: useful inventory/observation with gaps, or interruption",
        "  exit 4: no usable requested inventory/observation",
    ]
}

/// Exit-code lines for sectioned doctor vetting: checks fail
/// closed (exit 4 covers both failed checks and refused package
/// admission); there is no PARTIAL exit 3 and no policy verdict.
pub(crate) fn exit_code_help_doctor() -> [&'static str; 4] {
    [
        "  exit 0: preflight passed",
        "  exit 1: internal failure",
        "  exit 2: invalid arguments",
        "  exit 4: checks failed or package admission refused (fail-closed)",
    ]
}

/// Exit-code lines for doctor capability checks (focused
/// self-controls, discovery): unavailable lands on exit 3; there
/// is no fail-closed exit 4 and no policy verdict.
pub(crate) fn exit_code_help_doctor_capability() -> [&'static str; 4] {
    [
        "  exit 0: all capabilities available",
        "  exit 1: output failure",
        "  exit 2: invalid arguments",
        "  exit 3: capabilities unavailable",
    ]
}

/// Exit-code lines for the legacy exact-profile diagnostic
/// (bare `doctor --libcrypto`): checks fail closed; there is no
/// internal-failure exit 1, no PARTIAL 3, no policy verdict.
pub(crate) fn exit_code_help_doctor_profiled() -> [&'static str; 3] {
    [
        "  exit 0: preflight passed (preflight only)",
        "  exit 2: invalid arguments",
        "  exit 4: preflight failed (fail-closed)",
    ]
}

/// Exit-code lines for report: a finalized observation with no
/// policy evaluation (the outcome is Pass/NoVerdict only), so
/// 10/11 are unemittable; PARTIAL lands on 3, setup refusal on 4.
pub(crate) fn exit_code_help_report() -> [&'static str; 5] {
    [
        "  exit 0: completed report",
        "  exit 1: child, artifact-delivery, or runtime failure",
        "  exit 2: invalid arguments or explicit companion",
        "  exit 3: PARTIAL report",
        "  exit 4: setup/environment refusal without usable observation (no verdict)",
    ]
}

/// One help line per exit code (mirrors docs/usage.md#exit-codes).
/// Exits 3/4 additionally print their single stderr reason at runtime
/// (see `report::exit_reason_line`).
/// Service exits (§7.3 fold + coordinator refusals; UX4b).
pub(crate) fn exit_code_help_service() -> [&'static str; 7] {
    [
        "  exit 0: clean run (help or uninterrupted complete windows)",
        "  exit 1: delivery/tool failure or fatal salvaged",
        "  exit 2: invalid arguments or refusal",
        "  exit 3: partial/interrupted run",
        "  exit 4: setup refusal, zero windows, or no verdict",
        "  exit 10: definite policy violation (takes precedence)",
        "  exit 11: policy inconclusive (Unknown-only evidence)",
    ]
}

pub(crate) fn exit_code_help() -> [&'static str; 7] {
    [
        "  exit 0: ok (help or successful controls; no complete-execution claim)",
        "  exit 1: child, artifact-delivery, or runtime failure",
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
    "  blocked? run 'osslscope doctor' first ('--pid PID' for a foreign target); '<cmd> --help' names that command's exits"
}

/// First-run pointer for subcommand helps (printed after the exit
/// lines): the doctor command diagnoses; help texts do not.
pub(crate) fn blocked_pointer_sub() -> &'static str {
    "  first run blocked? bare 'doctor' checks self (CAP_BPF+CAP_PERFMON); 'doctor --pid PID' probes foreign backing (needs root/capable proof)"
}

/// Attach warning for live-observation `--help` texts (G4 U5/S1):
/// one shared line — privileged, system-wide, finite window.
/// Printed after the usage block, before the exit lines.
pub(crate) fn attach_warning_help() -> &'static str {
    "  warning: live observation is privileged and system-wide; every observation window is finite"
}

/// One-line runtime notice, emitted once per process when the
/// first BPF attach begins (G4 U5/S1). Stderr only; complements
/// the later per-run `focused callbacks attached` confirmation.
pub(crate) fn attach_notice_line() -> &'static str {
    "osslscope: note: live observation starting (privileged, system-wide probes; finite window)"
}

/// First-attach latch shared by all three notice variants:
/// exactly one line per process, first proven attach wins,
/// whichever route it comes from. A lock + flag (not `Once`)
/// so a SKIPPED bounded write leaves the latch unfired for a
/// later attempt. Lock order: notice lock, then the stderr lock
/// inside `err_line[_bounded]` — never the reverse.
static NOTICE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static NOTICE_FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Detailed variant (S1 audit text): names the target pid and the
/// observation window. Routes without a single pid/window (provider
/// observation) keep the generic line.
pub(crate) fn attach_notice_line_detail(detail: &str) -> String {
    format!("osslscope: note: live observation starting (privileged, system-wide probes; {detail})")
}

/// Emit [`attach_notice_line`] exactly once per process, at the
/// first successful session open. Call sites prove attachment
/// (an open plane), never an attempt: denied hosts stay silent.
pub(crate) fn note_attach_start() {
    let _guard = NOTICE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if NOTICE_FIRED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    crate::report::err_line(attach_notice_line());
    NOTICE_FIRED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Detailed variant of [`note_attach_start`]: `detail` names the
/// target and window (e.g. `pid 123, 5s window`). Same once latch.
pub(crate) fn note_attach_start_detail(detail: &str) {
    let _guard = NOTICE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if NOTICE_FIRED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    crate::report::err_line(&attach_notice_line_detail(detail));
    NOTICE_FIRED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Best-effort variant of [`note_attach_start_detail`] for
/// stopped-child setups: the notice must never stall a stopped
/// child on a saturated stderr pipe past `deadline` — skip
/// silently instead (the latch stays unfired, so a later attach
/// can still report). Same once latch on success.
pub(crate) fn note_attach_start_detail_bounded(detail: &str, deadline: std::time::Instant) {
    let _guard = NOTICE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if NOTICE_FIRED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    if crate::report::err_line_bounded(&attach_notice_line_detail(detail), deadline) {
        NOTICE_FIRED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// One-line runtime notice, emitted once per process when a
/// selector-less live watch starts (S2): without
/// --pid/--cgroup/--module the watch attempts the whole visible
/// population. Stderr only; warns (never refuses) to preserve the
/// whole-population workflow and legacy behavior.
pub(crate) fn selectorless_watch_notice_line() -> &'static str {
    "osslscope: note: selector-less live watch observes the whole visible population; narrow with --pid/--cgroup/--module"
}

/// Emit [`selectorless_watch_notice_line`] once per process.
pub(crate) fn note_selectorless_watch() {
    static NOTICED: std::sync::Once = std::sync::Once::new();
    NOTICED.call_once(|| {
        crate::report::err_line(selectorless_watch_notice_line());
    });
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

/// Doctor dispatch route (precedence: discovery > sectioned
/// (--libcrypto with a sectioned flag is a vetting intent) >
/// profiled (bare --libcrypto only) > focused).
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
    } else if SECTIONED.iter().any(|f| flags.contains(f)) {
        // Sectioned selectors route to sectioned vetting — including
        // --libcrypto combos (vetting intents: the sectioned parser
        // vets --libcrypto with enrollment flags and rejects two
        // target selectors with one clear usage error).
        DoctorRoute::Sectioned
    } else if flags.contains(&"--libcrypto") {
        // Bare --libcrypto (+ shared --count-object/--format
        // companions only): the historical v0.2 exact-profile
        // diagnostic (usage.md "Legacy foreground diagnostic").
        DoctorRoute::Profiled
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
        "service" => crate::service::run(&argv[1..]),
        "service-witness" => crate::service::witness_cli::run(&argv[1..]),
        "service-attempt-trace" => crate::service::witness_cli::run_trace(&argv[1..]),
        "report" => crate::report::run(&argv[1..]),
        "check" => crate::check::run(&argv[1..]),
        "export" => crate::presentation::export::run(&argv),
        "watch" => crate::presentation::watch::run(&argv),
        "help" | "--help" | "-h" => {
            // G4 U3b: `help <sub>` honors its argument (byte-identical
            // to `<sub> --help`); unknown topics stay usage errors.
            if let Some(topic) = argv.get(1).map(String::as_str) {
                return help_topic(topic);
            }
            println!("osslscope — non-interposing OpenSSL observer");
            println!(
                "usage: osslscope <scan|inspect|doctor|report|check|alias-audit|service|export|watch> [args]"
            );
            // G4 U3a: scan/inspect are first-class bullets (the
            // unprivileged on-ramp), not a footer aside.
            println!("  scan         passive process/module discovery; no profile or BPF required");
            println!("  inspect      passive per-target detail; no profile or BPF required");
            println!(
                "  doctor       inventory, companion integrity and functional tracing preflight"
            );
            println!(
                "  report       observe learned callbacks in one selected PID or foreground run"
            );
            println!("  check        policy gate over a window (CI use; exits 10 on violation)");
            println!(
                "  service      bounded-window continuous observation service (see: service --help)"
            );
            println!("  alias-audit  group a harvest doc's rows by shared address");
            println!(
                "  export       serve Prometheus exposition + OTLP push from a service out-DIR"
            );
            println!("  watch        render one operator frame from a service out-DIR");
            println!(
                "  report/check use --pid PID or run -- COMMAND; --libcrypto selects legacy diagnostics"
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
        "--version" | "-V" | "version" => {
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

/// `help <topic>` dispatch (G4 U3b): a known subcommand renders
/// its own `--help` (byte-identical to the direct form); `help`
/// and `version` topics render the top help and version line;
/// anything else is the standard unknown-subcommand error.
fn help_topic(topic: &str) -> ExitCode {
    match topic {
        "help" | "--help" | "-h" => run(["help".to_string()].into_iter()),
        "--version" | "-V" | "version" => run(["--version".to_string()].into_iter()),
        "scan"
        | "inspect"
        | "doctor"
        | "report"
        | "check"
        | "alias-audit"
        | "service"
        | "export"
        | "watch"
        | "service-witness"
        | "service-attempt-trace" => run([topic.to_string(), "--help".to_string()].into_iter()),
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
        // Precedence: discovery > sectioned > profiled (bare
        // --libcrypto only).
        assert_eq!(
            route(&["--discovery", "--pid", "1"]),
            DoctorRoute::Discovery
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--pid", "1"]),
            DoctorRoute::Sectioned
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
    fn doctor_route_libcrypto_vetting_combos_reach_sectioned() {
        fn route(words: &[&str]) -> DoctorRoute {
            doctor_route(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>())
        }
        // Bare --libcrypto (+ shared companions only) stays on the
        // historical v0.2 exact-profile diagnostic.
        assert_eq!(route(&["--libcrypto", "lib"]), DoctorRoute::Profiled);
        assert_eq!(
            route(&["--libcrypto", "lib", "--count-object", "c"]),
            DoctorRoute::Profiled
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--format", "json"]),
            DoctorRoute::Profiled
        );
        assert_eq!(
            route(&["--libcrypto", "x", "--help"]),
            DoctorRoute::Profiled
        );
        // Vetting intents reach the sectioned vetting path (whose
        // USAGE advertises --libcrypto and whose parser vets it).
        assert_eq!(
            route(&["--libcrypto", "lib", "--table", "t"]),
            DoctorRoute::Sectioned
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--force-offset", "1"]),
            DoctorRoute::Sectioned
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--provider-table", "p"]),
            DoctorRoute::Sectioned
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--object", "o"]),
            DoctorRoute::Sectioned
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--members-object", "m"]),
            DoctorRoute::Sectioned
        );
        // A second target selector is a sectioned usage error, never
        // a v0.2 profiled rejection.
        assert_eq!(
            route(&["--libcrypto", "lib", "--pid", "1"]),
            DoctorRoute::Sectioned
        );
        assert_eq!(
            route(&["--libcrypto", "lib", "--exe", "x"]),
            DoctorRoute::Sectioned
        );
        // Discovery still wins over everything.
        assert_eq!(
            route(&["--discovery", "--libcrypto", "lib"]),
            DoctorRoute::Discovery
        );
        // Documented legacy conflicts keep the legacy route.
        assert_eq!(
            route(&["--libcrypto", "lib", "--observation-object", "o"]),
            DoctorRoute::Profiled
        );
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
    fn attach_warning_lines_name_privilege_scope_and_window() {
        // G4 U5/S1: both the --help warning and the runtime notice
        // carry the three wording elements.
        for line in [attach_warning_help(), attach_notice_line()] {
            assert!(line.contains("privileged"), "{line}");
            assert!(line.contains("system-wide"), "{line}");
            assert!(line.contains("finite"), "{line}");
        }
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

    /// Swap fd 2 onto `new_fd`, restoring on drop (panic-safe).
    /// Single-threaded suite only: fd 2 is process-global. Tests
    /// must still drop explicitly before asserting, so a failure
    /// panic never itself writes to the swapped fd.
    struct Fd2Guard {
        saved: std::os::unix::io::RawFd,
    }

    impl Fd2Guard {
        fn swap(new_fd: std::os::unix::io::RawFd) -> Self {
            let saved = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved >= 0);
            let guard = Self { saved };
            assert_eq!(
                unsafe { libc::dup2(new_fd, libc::STDERR_FILENO) },
                libc::STDERR_FILENO
            );
            guard
        }
    }

    impl Drop for Fd2Guard {
        fn drop(&mut self) {
            unsafe {
                libc::dup2(self.saved, libc::STDERR_FILENO);
                libc::close(self.saved);
            }
        }
    }

    /// S1: the bounded write honors an expired deadline
    /// without polling (deterministic skip).
    #[test]
    fn stderr_bounded_expired_deadline_skips() {
        let past = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(!crate::report::err_line_bounded("unseen", past));
    }

    /// S1: the bounded write passes on a writable stderr
    /// (captured test pipe has room).
    #[test]
    fn stderr_bounded_writable_stderr_passes() {
        let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
        assert!(crate::report::err_line_bounded("probe-line", future));
    }

    /// S1: a saturated stderr pipe skips within the notice
    /// budget instead of blocking (the pipe starts full, so even
    /// the first write would stall a blocking writer). Swaps fd 2
    /// onto a filled pipe for the call only; a guard restores it
    /// (panic-safe, and the suite runs single-threaded).
    #[test]
    fn stderr_bounded_saturated_pipe_skips_fast() {
        // Fill a pipe to saturation (nonblocking fill loop).
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rfd, wfd) = (fds[0], fds[1]);
        let flags = unsafe { libc::fcntl(wfd, libc::F_GETFL) };
        unsafe {
            libc::fcntl(wfd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let chunk = vec![0u8; 65536];
        loop {
            let r = unsafe { libc::write(wfd, chunk.as_ptr() as *const libc::c_void, chunk.len()) };
            if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
                break;
            }
            assert!(r > 0);
        }
        // Swap fd 2 onto the saturated pipe (guard restores).
        let _guard = Fd2Guard::swap(wfd);
        // The bounded write must skip within its budget (~250ms),
        // never block: generous 5s bound, no timing assumption.
        // Restore fd 2 BEFORE asserting, so a failure panic never
        // itself blocks on the saturated pipe.
        let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let start = std::time::Instant::now();
        let skipped = !crate::report::err_line_bounded("unseen-by-design", future);
        let elapsed = start.elapsed();
        drop(_guard);
        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
        assert!(skipped, "saturated pipe must skip");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "bounded skip took {elapsed:?}"
        );
    }

    /// S1: file stderr keeps shared-description semantics —
    /// interleaved bounded + plain writes land complete and
    /// ordered (no offset-0 clobber, no stale-offset overwrite).
    /// Swaps fd 2 onto a temp file for the writes only; a guard
    /// restores it (panic-safe, single-threaded suite).
    #[test]
    fn stderr_bounded_file_stderr_appends_intact() {
        use std::os::unix::io::AsRawFd as _;
        let path = std::env::temp_dir().join(format!("bounded-file-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let _guard = Fd2Guard::swap(file.as_raw_fd());
        let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
        assert!(crate::report::err_line_bounded("first", future));
        crate::report::err_line("second");
        assert!(crate::report::err_line_bounded("third", future));
        drop(_guard);
        drop(file);
        let content = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(content, "first\nsecond\nthird\n");
    }

    /// S1: socket stderr (systemd journal shape) delivers through
    /// `send(MSG_DONTWAIT)`: swap fd 2 onto one end of a
    /// socketpair, read the line back from the other end. The
    /// read end goes nonblocking first, so a regression fails
    /// loudly instead of hanging.
    #[test]
    fn stderr_bounded_socket_delivers() {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let (rfd, wfd) = (fds[0], fds[1]);
        let flags = unsafe { libc::fcntl(rfd, libc::F_GETFL) };
        unsafe {
            libc::fcntl(rfd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let _guard = Fd2Guard::swap(wfd);
        let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let delivered = crate::report::err_line_bounded("sock-line", future);
        drop(_guard);
        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(rfd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
        assert!(delivered, "socket stderr must deliver");
        assert!(n > 0, "nothing arrived on the socket");
        assert_eq!(&buf[..n as usize], b"sock-line\n");
    }

    /// S1: a saturated socket skips within budget (never blocks):
    /// fill one end with no reader, swap fd 2 onto it, expect a
    /// fast skip. Guarded to fail loudly (not hang) on regress.
    #[test]
    fn stderr_bounded_saturated_socket_skips_fast() {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let (rfd, wfd) = (fds[0], fds[1]);
        let flags = unsafe { libc::fcntl(wfd, libc::F_GETFL) };
        unsafe {
            libc::fcntl(wfd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let chunk = vec![0u8; 65536];
        let mut saturated = false;
        for _ in 0..128 {
            let r = unsafe {
                libc::send(
                    wfd,
                    chunk.as_ptr() as *const libc::c_void,
                    chunk.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
                saturated = true;
                break;
            }
            assert!(r > 0);
        }
        assert!(saturated, "socket never saturated: vacuous test");
        let _guard = Fd2Guard::swap(wfd);
        let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let start = std::time::Instant::now();
        let skipped = !crate::report::err_line_bounded("unseen-by-design", future);
        let elapsed = start.elapsed();
        drop(_guard);
        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
        assert!(skipped, "saturated socket must skip");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "bounded skip took {elapsed:?}"
        );
    }

    /// S1: character-device stderr takes the private path:
    /// `/dev/null` delivers, `/dev/full` fails fast (no hang,
    /// no panic). Pins the fstat routing for the chr branch.
    #[test]
    fn stderr_bounded_char_devices() {
        let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
        assert!(null >= 0);
        let full = unsafe { libc::open(c"/dev/full".as_ptr(), libc::O_WRONLY) };
        assert!(full >= 0);
        let null_guard = Fd2Guard::swap(null);
        assert!(
            crate::report::err_line_bounded("null-line", future),
            "/dev/null must deliver"
        );
        drop(null_guard);
        let full_guard = Fd2Guard::swap(full);
        let start = std::time::Instant::now();
        assert!(
            !crate::report::err_line_bounded("full-line", future),
            "/dev/full must fail fast"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "/dev/full write took {elapsed:?}",
            elapsed = start.elapsed()
        );
        drop(full_guard);
        unsafe {
            libc::close(null);
            libc::close(full);
        }
    }

    /// S1: the detailed first-attach notice names the target pid
    /// and window (audit text); the generic line is unchanged.
    #[test]
    fn attach_notice_detail_names_pid_and_window() {
        assert_eq!(
            attach_notice_line_detail("pid 123, 5s window"),
            "osslscope: note: live observation starting (privileged, system-wide probes; pid 123, 5s window)"
        );
        assert_eq!(
            attach_notice_line(),
            "osslscope: note: live observation starting (privileged, system-wide probes; finite window)"
        );
    }
}
