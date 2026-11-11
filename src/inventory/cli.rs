// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive inventory commands. User supplied strings never enter diagnostics.
use super::{
    Capabilities, GapReason, InventoryState, Limits, ModuleInfo, ObservationState, SnapshotOptions,
    SnapshotPreamble, WorkTotals, elf, snapshot,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal as _, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const HELP: &str = "usage: osslscope scan [--pid PID ...] [--cgroup PATH] [--module PATH ...] [--watch [--interval S] [--duration S]] [--json] [--resolve-paths]\n       osslscope inspect --pid PID [--json] [--resolve-paths]\n       osslscope inspect --module PATH [--module PATH ...] [--json] [--resolve-paths]\nAdd --observe-crypto to scan --watch for automatic per-process crypto observations.\n--resolve-paths renders verified host paths on TTY-attached human rows (default off; discovery JSON carries machine path evidence; never in diagnostics).\nPassive file-backed inventory; ELF exports and mappings do not prove activation or execution.\nProvider activation/interfaces remain unknown; execution is not_observed.\n";
const MEANING: &str = "Passive inventory: ELF exports and mappings do not prove activation or execution.\nProvider activation/interfaces: unknown; execution: not_observed.\n";
/// Value-taking options of [`parse`]: the scan router consumes the
/// token after each of these, so flag-shaped values never misroute.
/// A new value-taking match arm MUST extend this list.
pub(crate) const VALUE_OPTIONS: &[&str] =
    &["--interval", "--duration", "--pid", "--module", "--cgroup"];

/// Effective `--resolve-paths` acquisition gate (external F2 as
/// amended by v0.6.0 D1): D1 rejected the never-in-JSON gate —
/// locator establishment + sidecar staging + machine path
/// evidence (`verified_path` via H4 custody, `maps_spelling`
/// hint) run for JSON output and flagged runs alike. The
/// terminal gates ONLY the human `path=` fragment (`render_paths`
/// at the call sites); redirected human output still renders
/// `(not-a-terminal)` placeholders from the raw flag (cell 6).
pub(crate) fn acquire_paths(resolve_paths: bool, json: bool, _terminal: bool) -> bool {
    resolve_paths || json
}

pub(crate) struct Options {
    pub(crate) pids: Vec<u32>,
    pub(crate) modules: Vec<PathBuf>,
    pub(crate) cgroup: Option<PathBuf>,
    pub(crate) json: bool,
    pub(crate) watch: bool,
    pub(crate) interval: Option<Duration>,
    pub(crate) duration: Option<Duration>,
    /// T5 `--resolve-paths` (rule 1): argv only, default off. No
    /// config-file or env enablement exists anywhere (cell 7).
    pub(crate) resolve_paths: bool,
}
pub(crate) fn parse(command: &str, args: &[String]) -> Result<Options, ()> {
    parse_inner(command, args, false)
}
pub(crate) fn parse_crypto_watch(args: &[String]) -> Result<Options, ()> {
    parse_inner("scan", args, true)
}
fn parse_inner(command: &str, args: &[String], allow_crypto: bool) -> Result<Options, ()> {
    let mut crypto = false;
    let mut options = Options {
        pids: Vec::new(),
        modules: Vec::new(),
        json: false,
        cgroup: None,
        watch: false,
        interval: None,
        duration: None,
        resolve_paths: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" if !options.json => options.json = true,
            "--resolve-paths" if !options.resolve_paths => options.resolve_paths = true,
            "--observe-crypto" if allow_crypto && !crypto => crypto = true,
            "--watch" if command == "scan" && !options.watch => options.watch = true,
            "--interval" if command == "scan" && options.interval.is_none() => {
                options.interval = Some(seconds(args.next().ok_or(())?, true)?);
            }
            "--duration" if command == "scan" && options.duration.is_none() => {
                options.duration = Some(seconds(args.next().ok_or(())?, false)?);
            }
            "--pid" => {
                let text = args.next().ok_or(())?;
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(());
                }
                let pid: u32 = text.parse().map_err(|_| ())?;
                if pid == 0 || pid > i32::MAX as u32 {
                    return Err(());
                }
                options.pids.push(pid);
            }
            "--module" => {
                let path = args.next().ok_or(())?;
                if path.is_empty() || path.starts_with("--") {
                    return Err(());
                }
                options.modules.push(PathBuf::from(path));
            }
            "--cgroup" if command == "scan" && options.cgroup.is_none() => {
                let path = args.next().ok_or(())?;
                if path.is_empty() || path.starts_with("--") {
                    return Err(());
                }
                options.cgroup = Some(PathBuf::from(path));
            }
            _ => return Err(()),
        }
    }
    if allow_crypto && (!crypto || !options.watch) {
        return Err(());
    }
    if !options.watch && (options.interval.is_some() || options.duration.is_some()) {
        return Err(());
    }
    if command == "inspect"
        && !((options.pids.len() == 1 && options.modules.is_empty())
            || (options.pids.is_empty() && !options.modules.is_empty()))
    {
        return Err(());
    }
    if command != "scan" && command != "inspect" {
        return Err(());
    }
    Ok(options)
}

fn seconds(text: &str, interval: bool) -> Result<Duration, ()> {
    let seconds: f64 = text.parse().map_err(|_| ())?;
    if !seconds.is_finite() || seconds <= 0.0 || seconds > 3600.0 || (interval && seconds < 0.05) {
        return Err(());
    }
    let duration = Duration::try_from_secs_f64(seconds).map_err(|_| ())?;
    if duration.is_zero() {
        return Err(());
    }
    Ok(duration)
}

static WATCH_INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn watch_signal(_: libc::c_int) {
    WATCH_INTERRUPTED.store(true, Ordering::Relaxed);
}
/// CLI lifetime only: save/restore the observer's exact dispositions. The
/// library API uses its caller's AtomicBool and never changes signal state.
struct WatchSignals(Vec<(libc::c_int, libc::sigaction)>);
impl WatchSignals {
    fn install() -> io::Result<Self> {
        WATCH_INTERRUPTED.store(false, Ordering::Relaxed);
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: both sigaction values are initialized, sigemptyset
            // initializes the mask, and this handler only stores an atomic.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = watch_signal as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(io::Error::last_os_error());
            }
            guard.0.push((signal, previous));
        }
        Ok(guard)
    }
}
impl Drop for WatchSignals {
    fn drop(&mut self) {
        for (signal, previous) in self.0.iter().rev() {
            // SAFETY: restoring the exact initialized disposition saved above.
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}

#[derive(Serialize)]
struct ModuleError {
    input_index: usize,
    reason: GapReason,
}
#[derive(Serialize)]
struct ModuleInventory {
    schema_version: &'static str,
    mode: &'static str,
    modules: Vec<ModuleInfo>,
    errors: Vec<ModuleError>,
    /// Render-time row capabilities (T5 `--resolve-paths` rule 3),
    /// skipped by serde — machine bytes flag-independent (cell 2).
    /// Locator provenance here is operator argv (observer-side),
    /// still canonicalized + identity-checked at render.
    #[serde(skip)]
    resolve: super::resolve::ResolveSidecar,
    totals: WorkTotals,
    limits: Limits,
    capabilities: Capabilities,
}
type FileKey = (u64, u64, u64, i64, i64, i64, i64);
fn file_key(metadata: &std::fs::Metadata) -> FileKey {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}
fn inspect_modules(paths: &[PathBuf], limits: Limits, resolve_paths: bool) -> ModuleInventory {
    let started = Instant::now();
    let mut result = ModuleInventory {
        schema_version: "osslscope.discovery.v1",
        mode: "module",
        modules: Vec::new(),
        errors: Vec::new(),
        totals: WorkTotals::default(),
        limits,
        resolve: super::resolve::ResolveSidecar::default(),
        capabilities: Capabilities {
            inventory: InventoryState::Complete,
            provider_activation: ObservationState::Unknown,
            provider_interfaces: ObservationState::Unknown,
            execution: ObservationState::NotObserved,
        },
    };
    // Retain descriptors so cached inode identities cannot be recycled. Both
    // successful and failed bounded reads are cached for this invocation only.
    let mut cache: BTreeMap<FileKey, (File, Result<ModuleInfo, GapReason>)> = BTreeMap::new();
    // Deferred `--resolve-paths` staging (external F3): (cache
    // key, operator argv) recorded during the machine loop,
    // materialized AFTER all machine acquisition so retained
    // dups cannot starve later inventory opens of FDs.
    let mut resolve_staged: Vec<(FileKey, PathBuf)> = Vec::new();
    for (input_index, path) in paths.iter().enumerate() {
        let reason = if started.elapsed() >= result.limits.timeout {
            Some(GapReason::Deadline)
        } else if result.totals.objects_attempted >= result.limits.max_objects {
            Some(GapReason::ObjectLimit)
        } else {
            None
        };
        if let Some(reason) = reason {
            result.errors.push(ModuleError {
                input_index,
                reason,
            });
            break;
        }
        result.totals.objects_attempted += 1;
        let inspected = (|| {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
                .open(path)
                .map_err(|_| GapReason::Unavailable)?;
            let metadata = file.metadata().map_err(|_| GapReason::Unavailable)?;
            if !metadata.is_file() {
                return Err(GapReason::NonRegular);
            }
            if metadata.len() > result.limits.max_module_bytes {
                return Err(GapReason::TooLarge);
            }
            if started.elapsed() >= result.limits.timeout {
                return Err(GapReason::Deadline);
            }
            let key = file_key(&metadata);
            if let Some((_, cached)) = cache.get(&key) {
                return cached.clone().map(|_| None);
            }
            let charge = metadata.len().checked_add(1).ok_or(GapReason::ReadLimit)?;
            if charge
                > result
                    .limits
                    .max_read_bytes
                    .saturating_sub(result.totals.read_bytes)
            {
                return Err(GapReason::ReadLimit);
            }
            result.totals.read_bytes += charge;
            // Bound any growth between admission and the parser's fstat to the
            // already charged length; inspect_file checks descriptor stability.
            result.totals.objects_inspected += 1;
            let parsed = elf::inspect_file(&mut file, metadata.len());
            if started.elapsed() >= result.limits.timeout {
                return Err(GapReason::Deadline);
            }
            let parsed = match file.metadata() {
                Ok(after) if file_key(&after) == key => parsed,
                _ => Err(GapReason::Changed),
            };
            cache.insert(key, (file, parsed.clone()));
            parsed.map(|info| Some((info, key)))
        })();
        match inspected {
            Ok(Some((info, key))) => {
                if resolve_paths {
                    resolve_staged.push((key, path.clone()));
                }
                result.modules.push(info);
            }
            Ok(None) => (),
            Err(reason) => result.errors.push(ModuleError {
                input_index,
                reason,
            }),
        }
    }
    // Materialize deferred capabilities AFTER all machine
    // acquisition (external F3). Locator provenance is operator
    // argv (observer-side): absolutized, never trusted — render
    // still opens it constrained and identity-matches. Clone,
    // absolutize, and dedicated-budget failures skip the row
    // (render `(unavailable)`); machine records are already fixed.
    if resolve_paths {
        let mut resolve_bytes = 0usize;
        for (key, argv) in &resolve_staged {
            let Some((file, Ok(info))) = cache.get(key) else {
                continue;
            };
            let locator = if argv.is_absolute() {
                Some(argv.clone())
            } else {
                std::env::current_dir().ok().map(|cwd| cwd.join(argv))
            };
            let charge = locator
                .as_ref()
                .map(|locator| locator.as_os_str().len())
                .unwrap_or(0)
                + 512;
            let Some(total) = resolve_bytes.checked_add(charge) else {
                continue;
            };
            if total > super::resolve::RESOLVE_BUDGET_BYTES {
                continue;
            }
            let Ok(dup) = file.try_clone() else {
                continue;
            };
            resolve_bytes = total;
            result.resolve.push(super::resolve::RowCapability::new(
                (info.device, info.inode),
                dup,
                locator,
            ));
        }
    }
    result.capabilities.inventory = if result.errors.is_empty() {
        InventoryState::Complete
    } else if result.modules.is_empty() {
        InventoryState::Unavailable
    } else {
        InventoryState::Partial
    };
    result
}
fn inventory_exit(state: InventoryState) -> u8 {
    match state {
        InventoryState::Complete => 0,
        InventoryState::Partial => 3,
        InventoryState::Unavailable => 4,
    }
}

/// Stderr reason for snapshot/module exits 3/4, derived from the same
/// `InventoryState` the exit code derives from. Gap words repeat the
/// rendered records (same `GapReason::word` vocabulary); `None` on
/// Complete.
fn inventory_exit_reason(state: InventoryState, reasons: &[GapReason]) -> Option<String> {
    let state_word = match state {
        InventoryState::Complete => return None,
        InventoryState::Partial => "partial",
        InventoryState::Unavailable => "unavailable",
    };
    let mut words: Vec<&str> = reasons.iter().map(GapReason::word).collect();
    words.sort_unstable();
    words.dedup();
    let detail = if words.is_empty() {
        "no gaps named".to_string()
    } else {
        let shown = words.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        if words.len() > 3 {
            format!("{shown} (+{} more)", words.len() - 3)
        } else {
            shown
        }
    };
    let count = if reasons.len() == 1 {
        "1 gap".to_string()
    } else {
        format!("{} gaps", reasons.len())
    };
    Some(format!(
        "osslscope discovery: inventory {state_word}: {detail} ({count}; see records above)"
    ))
}
/// Human identity summary: verified-vs-locator module counts plus
/// the verified share (P1-human-counts). JSON mode never sees it.
fn identity_line(verified: usize, locator: usize) -> String {
    super::identity_totals_line(verified, locator)
}

/// Coalesced gap block: one line per (reason, device, pid) group
/// with exact counters (P1-coalesce, display-only). Empty when the
/// snapshot carries no gaps.
fn gap_block(groups: &[(GapReason, Option<u64>, Option<u32>, usize)]) -> String {
    // Delegates to the shared core: groups arrive pre-counted from
    // coalesce_gaps, so each triple repeats per its count (counts are
    // small; clarity over micro-efficiency on the human path).
    super::gap_groups_block(
        groups.iter().flat_map(|(reason, device, pid, count)| {
            std::iter::repeat_n((reason.word(), *device, *pid), *count)
        }),
        "",
    )
}

fn render(
    value: &impl Serialize,
    json: bool,
    writer: &mut impl Write,
    preamble: Option<&SnapshotPreamble>,
    object_rows: &[String],
) -> io::Result<()> {
    if !json {
        writer.write_all(MEANING.as_bytes())?;
        // Snapshot paths pass their preamble; operator-supplied
        // module lists (inspect --module) have no process binding
        // to verify, so they pass None and omit the block.
        if let Some(pre) = preamble {
            let (verified, locator) = pre.identity;
            writer.write_all(identity_line(verified, locator).as_bytes())?;
            writer.write_all(gap_block(&pre.gap_groups).as_bytes())?;
            if pre.conclusively_without_openssl {
                writer.write_all(super::blindness_line().as_bytes())?;
            }
        }
        // T5 `--resolve-paths` object rows (TTY-only writer output;
        // empty unless the flag is on — preamble byte-identical).
        for row in object_rows {
            writeln!(writer, "{row}")?;
        }
    }
    serde_json::to_writer_pretty(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}
/// Validate the whole command before accessing procfs or supplied files.
pub fn run(command: &str, args: &[String]) -> ExitCode {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let outcome = if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        output
            .write_all(HELP.as_bytes())
            .and_then(|()| {
                for line in crate::cli::exit_code_help_observation() {
                    writeln!(output, "{line}")?;
                }
                writeln!(output, "{}", crate::cli::blocked_pointer_sub())?;
                Ok(())
            })
            .and_then(|()| output.flush())
            .map(|()| 0)
    } else {
        let options = match parse(command, args) {
            Ok(options) => options,
            Err(()) => {
                crate::report::err_line(
                    "osslscope discovery: invalid arguments (see scan --help or inspect --help)",
                );
                return ExitCode::from(2);
            }
        };
        // F2 gate inputs as amended by v0.6.0 D1 (never-in-JSON
        // gate rejected): acquisition runs for JSON output and
        // flagged runs alike; writers keep the raw flag (plus a
        // JSON veto) so redirected human rows still placeholder.
        let terminal = output.is_terminal();
        let acquire = acquire_paths(options.resolve_paths, options.json, terminal);
        let render_paths = options.resolve_paths && !options.json;
        if options.watch {
            let _signals = match WatchSignals::install() {
                Ok(guard) => guard,
                Err(_) => {
                    crate::report::err_line("osslscope discovery: observer signal setup failed");
                    return ExitCode::from(1);
                }
            };
            super::watch::run_formatted(
                &super::watch::WatchOptions {
                    selection: super::scope::Selection {
                        pids: options.pids,
                        cgroup: options.cgroup,
                        modules: options.modules,
                        resolve_paths: acquire,
                    },
                    interval: options.interval.unwrap_or(Duration::from_secs(1)),
                    duration: options.duration,
                    limits: Limits::default(),
                    resolve_paths: render_paths,
                },
                &mut output,
                &WATCH_INTERRUPTED,
                !options.json,
                terminal,
            )
            .map(|outcome| {
                if let Some(line) = super::watch::exit_reason(&outcome) {
                    crate::report::err_line(&line);
                }
                outcome.exit_code()
            })
        } else if command == "scan" {
            // Read before the Selection move below consumes the vectors.
            let module_scoped = !options.modules.is_empty();
            let mut scanner = match super::scope::ScopedScanner::new(
                super::scope::Selection {
                    pids: options.pids,
                    cgroup: options.cgroup,
                    modules: options.modules,
                    resolve_paths: acquire,
                },
                Limits::default(),
            ) {
                Ok(scanner) => scanner,
                Err(_) => {
                    // v0.6.0 D7: `--module` takes a file PATH only; a
                    // bare hash (or any other unopenable spelling)
                    // fails scope establishment, and the finite
                    // stderr line names the PATH form. The input
                    // itself and IO details never enter diagnostics.
                    // Digest selectors (`sha256:...`) are explicitly
                    // deferred to P1: not accepted in v0.6.
                    if module_scoped {
                        crate::report::err_line(
                            "osslscope discovery: requested scope unavailable (scan --module takes a file PATH, not a hash; see scan --help)",
                        );
                    } else {
                        crate::report::err_line("osslscope discovery: requested scope unavailable");
                    }
                    return ExitCode::from(4);
                }
            };
            let result = scanner.snapshot();
            let preamble = result.human_preamble();
            let writer = super::resolve::TerminalPathWriter::new(
                render_paths,
                output.is_terminal(),
                &result.resolve,
            );
            let rows = writer.object_rows(&result.processes);
            render(&result, options.json, &mut output, Some(&preamble), &rows).map(|()| {
                let reasons: Vec<GapReason> = result.gaps.iter().map(|g| g.reason).collect();
                if let Some(line) = inventory_exit_reason(result.capabilities.inventory, &reasons) {
                    crate::report::err_line(&line);
                }
                result.exit_code()
            })
        } else if options.modules.is_empty() {
            let result = snapshot(&SnapshotOptions {
                pids: options.pids,
                limits: Limits::default(),
                resolve_paths: acquire,
            });
            let preamble = result.human_preamble();
            let writer = super::resolve::TerminalPathWriter::new(
                render_paths,
                output.is_terminal(),
                &result.resolve,
            );
            let rows = writer.object_rows(&result.processes);
            render(&result, options.json, &mut output, Some(&preamble), &rows).map(|()| {
                let reasons: Vec<GapReason> = result.gaps.iter().map(|g| g.reason).collect();
                if let Some(line) = inventory_exit_reason(result.capabilities.inventory, &reasons) {
                    crate::report::err_line(&line);
                }
                result.exit_code()
            })
        } else {
            let result = inspect_modules(&options.modules, Limits::default(), acquire);
            let writer = super::resolve::TerminalPathWriter::new(
                render_paths,
                output.is_terminal(),
                &result.resolve,
            );
            let rows = writer.module_rows(&result.modules);
            render(&result, options.json, &mut output, None, &rows).map(|()| {
                let reasons: Vec<GapReason> = result.errors.iter().map(|e| e.reason).collect();
                if let Some(line) = inventory_exit_reason(result.capabilities.inventory, &reasons) {
                    crate::report::err_line(&line);
                }
                inventory_exit(result.capabilities.inventory)
            })
        }
    };
    match outcome {
        Ok(code) => ExitCode::from(code),
        Err(_) => {
            crate::report::err_line("osslscope discovery: output failed");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Architecture, CaptureInterval, FileVersionStatus, Gap, GapReason, IdentityAvailability,
        IdentityStatus, ModuleInfo, ModuleRecord, NamespaceIds, ObjectKind, ProcessRecord, Scope,
        ScopeRecord, Snapshot, SnapshotMode, coalesce_gaps,
    };
    use super::*;

    fn module_with(status: IdentityStatus) -> ModuleRecord {
        ModuleRecord {
            info: ModuleInfo {
                sha256: String::new(),
                device: 0,
                inode: 0,
                size_bytes: 0,
                architecture: Architecture::X86_64,
                kind: ObjectKind::Other,
                exports: Vec::new(),
                depends_on_libcrypto: false,
                depends_on_libssl: false,
                file_soname: None,
                file_openssl_version: None,
                file_version_status: FileVersionStatus::Absent,
            },
            identity_status: status,
            verified_path: None,
            verified_path_unavailable: None,
            maps_spelling: None,
        }
    }

    fn snapshot_with(modules: Vec<ModuleRecord>) -> Snapshot {
        let interval = CaptureInterval {
            started_unix_ms: None,
            finished_unix_ms: None,
            elapsed_ns: 0,
        };
        Snapshot {
            interval,
            scope_record: ScopeRecord::default(),
            schema_version: "osslscope.discovery.v1".into(),
            mode: SnapshotMode::Snapshot,
            scope: Scope::Pids,
            selected_pids: vec![1],
            processes: vec![ProcessRecord {
                interval: CaptureInterval {
                    started_unix_ms: None,
                    finished_unix_ms: None,
                    elapsed_ns: 0,
                },
                namespaces: NamespaceIds::default(),
                pid: 1,
                starttime: 0,
                comm: None,
                comm_status: IdentityAvailability::Unreadable,
                exe: None,
                exe_status: IdentityAvailability::Unreadable,
                modules,
                provider_activation: ObservationState::Unknown,
                provider_interfaces: ObservationState::Unknown,
                execution: ObservationState::NotObserved,
            }],
            gaps: Vec::new(),
            totals: WorkTotals::default(),
            limits: Limits::default(),
            capabilities: Capabilities {
                inventory: InventoryState::Complete,
                provider_activation: ObservationState::Unknown,
                provider_interfaces: ObservationState::Unknown,
                execution: ObservationState::NotObserved,
            },
            resolve: super::super::resolve::ResolveSidecar::default(),
            cgroup_identity: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn snapshot_identity_counts_verified_share() {
        let snap = snapshot_with(vec![
            module_with(IdentityStatus::Verified),
            module_with(IdentityStatus::LocatorCandidate),
        ]);
        assert_eq!(snap.identity_counts(), (1, 1));
        let empty = snapshot_with(Vec::new());
        assert_eq!(empty.identity_counts(), (0, 0));
    }

    #[test]
    fn human_render_reports_verified_share() {
        let snap = snapshot_with(vec![
            module_with(IdentityStatus::Verified),
            module_with(IdentityStatus::LocatorCandidate),
        ]);
        let preamble = snap.human_preamble();
        let mut buf = Vec::new();
        render(&snap, false, &mut buf, Some(&preamble), &[]).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("identity: 1 verified, 1 locator-candidate of 2 modules (50% verified)\n"),
            "{out}"
        );
        // No gaps: no grouped block.
        assert!(!out.contains("gaps ("), "{out}");
        // JSON mode carries no preamble at all.
        let mut buf = Vec::new();
        render(&snap, true, &mut buf, Some(&preamble), &[]).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("identity: "), "{out}");
        assert!(!out.contains("Passive inventory"), "{out}");
    }

    #[test]
    fn gap_reason_words_match_json() {
        // Every word mirrors the serde snake_case label exactly.
        for reason in [
            GapReason::Unavailable,
            GapReason::NonRegular,
            GapReason::TooLarge,
            GapReason::NotElf,
            GapReason::MalformedElf,
            GapReason::Changed,
            GapReason::UnsupportedArchitecture,
            GapReason::ProcessUnavailable,
            GapReason::IdentityUnverified,
            GapReason::BackingUnavailable,
            GapReason::ReadLimit,
            GapReason::ProcessLimit,
            GapReason::ObjectLimit,
            GapReason::MalformedMaps,
            GapReason::Deadline,
            GapReason::UnsupportedCgroup,
            GapReason::CgroupUnavailable,
            GapReason::CgroupLimit,
            GapReason::MembershipUnknown,
            GapReason::NamespaceUnavailable,
        ] {
            let json = serde_json::to_value(reason).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(reason.word().into()),
                "{reason:?}"
            );
        }
    }

    #[test]
    fn gap_refusal_fields_are_additive() {
        // Old documents without refusal fields still parse; bare gaps keep
        // their exact historical bytes.
        let bare: Gap =
            serde_json::from_str(r#"{"pid":7,"device":1,"inode":10,"reason":"too_large"}"#)
                .unwrap();
        assert_eq!(bare.errno, None);
        assert_eq!(bare.actor_euid, None);
        assert_eq!(
            serde_json::to_value(&bare).unwrap(),
            serde_json::json!({"pid":7,"device":1,"inode":10,"reason":"too_large"})
        );
        assert_eq!(
            serde_json::to_string(&bare).unwrap(),
            r#"{"pid":7,"device":1,"inode":10,"reason":"too_large"}"#
        );
        // A refused open round-trips with its errno and actor.
        let refused = Gap {
            pid: Some(7),
            device: Some(1),
            inode: Some(10),
            reason: GapReason::IdentityUnverified,
            errno: Some(libc::EPERM),
            actor_euid: Some(1001),
        };
        let value = serde_json::to_value(&refused).unwrap();
        assert_eq!(value["errno"], libc::EPERM);
        assert_eq!(value["actor_euid"], 1001);
        assert_eq!(serde_json::from_value::<Gap>(value).unwrap(), refused);
    }

    #[test]
    fn gaps_coalesce_by_reason_device_pid() {
        let gaps = vec![
            Gap {
                pid: Some(7),
                device: Some(1),
                inode: Some(10),
                reason: GapReason::TooLarge,
                errno: None,
                actor_euid: None,
            },
            Gap {
                pid: Some(7),
                device: Some(1),
                inode: Some(11),
                reason: GapReason::TooLarge,
                errno: None,
                actor_euid: None,
            },
            Gap {
                pid: Some(9),
                device: Some(1),
                inode: Some(12),
                reason: GapReason::TooLarge,
                errno: None,
                actor_euid: None,
            },
            Gap {
                pid: None,
                device: None,
                inode: None,
                reason: GapReason::Deadline,
                errno: None,
                actor_euid: None,
            },
        ];
        let groups = coalesce_gaps(&gaps);
        assert_eq!(
            groups,
            vec![
                (GapReason::TooLarge, Some(1), Some(7), 2),
                (GapReason::TooLarge, Some(1), Some(9), 1),
                (GapReason::Deadline, None, None, 1),
            ]
        );
        // Counters are exact: group sizes sum to the input length.
        assert_eq!(groups.iter().map(|g| g.3).sum::<usize>(), gaps.len());
    }

    #[test]
    fn human_render_coalesces_gaps() {
        let mut snap = snapshot_with(Vec::new());
        snap.gaps = vec![
            Gap {
                pid: Some(7),
                device: Some(1),
                inode: Some(10),
                reason: GapReason::TooLarge,
                errno: None,
                actor_euid: None,
            },
            Gap {
                pid: Some(7),
                device: Some(1),
                inode: Some(11),
                reason: GapReason::TooLarge,
                errno: None,
                actor_euid: None,
            },
        ];
        let preamble = snap.human_preamble();
        let mut buf = Vec::new();
        render(&snap, false, &mut buf, Some(&preamble), &[]).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("gaps (2 total in 1 group):\n"), "{out}");
        assert!(out.contains("  too_large device=1 pid=7: 2\n"), "{out}");
        // JSON mode carries the raw array, never the grouped block.
        let mut buf = Vec::new();
        render(&snap, true, &mut buf, Some(&preamble), &[]).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("gaps ("), "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["gaps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn module_limits_admit_no_io_when_object_or_deadline_budget_is_empty() {
        let paths = [PathBuf::from("/PRIVATE_CANARY_missing")];
        for (limits, reason) in [
            (
                Limits {
                    max_objects: 0,
                    ..Limits::default()
                },
                GapReason::ObjectLimit,
            ),
            (
                Limits {
                    timeout: std::time::Duration::ZERO,
                    ..Limits::default()
                },
                GapReason::Deadline,
            ),
        ] {
            let result = inspect_modules(&paths, limits, false);
            assert_eq!(result.errors[0].reason, reason);
            assert_eq!(result.totals.objects_attempted, 0);
            assert_eq!(result.totals.read_bytes, 0);
            assert_eq!(inventory_exit(result.capabilities.inventory), 4);
            assert!(
                !serde_json::to_string(&result)
                    .unwrap()
                    .contains("PRIVATE_CANARY")
            );
        }
    }

    #[test]
    fn acquire_gate_truth_table() {
        // External F2 as amended by v0.6.0 D1 (never-in-JSON gate
        // rejected): acquisition (locator establishment + sidecar
        // staging + machine path evidence) runs for JSON output
        // and flagged runs alike; only unflagged human output
        // bypasses. The terminal gates just the human `path=`
        // fragment (`render_paths`).
        assert!(acquire_paths(true, false, true));
        assert!(acquire_paths(true, false, false));
        assert!(acquire_paths(false, true, true));
        assert!(acquire_paths(false, true, false));
        assert!(acquire_paths(true, true, true));
        assert!(acquire_paths(true, true, false));
        assert!(!acquire_paths(false, false, true));
        assert!(!acquire_paths(false, false, false));
    }

    #[test]
    fn inspect_sidecar_populated_only_when_acquiring() {
        // F2 acquisition leg as amended by v0.6.0 D1
        // (never-in-JSON gate rejected): inputs flow through
        // `acquire_paths` — JSON output acquires even without the
        // flag; only unflagged human output stages nothing (no
        // retained FDs/bytes). The module route carries no machine
        // path keys, so its records stay identical either way
        // (discovery ModuleRecords differ when acquiring — see
        // `v060_json_paths_come_from_custody_not_maps_text`).
        let executable = PathBuf::from("/bin/true");
        let off = inspect_modules(
            std::slice::from_ref(&executable),
            Limits::default(),
            acquire_paths(false, false, false),
        );
        assert_eq!(off.modules.len(), 1);
        assert!(off.resolve.is_empty());
        let on = inspect_modules(
            std::slice::from_ref(&executable),
            Limits::default(),
            acquire_paths(false, true, false),
        );
        assert_eq!(on.modules.len(), 1);
        assert_eq!(on.resolve.len(), 1);
        // Machine records identical either way (module route has no path keys).
        assert_eq!(
            serde_json::to_value(&off).unwrap(),
            serde_json::to_value(&on).unwrap()
        );
    }

    #[test]
    fn module_read_admission_and_duplicate_cache_use_aggregate_budget() {
        let executable = PathBuf::from("/bin/true");
        let charge = std::fs::metadata(&executable).unwrap().len() + 1;
        let denied = inspect_modules(
            std::slice::from_ref(&executable),
            Limits {
                max_read_bytes: charge - 1,
                ..Limits::default()
            },
            false,
        );
        assert_eq!(denied.errors[0].reason, GapReason::ReadLimit);
        assert_eq!(denied.totals.read_bytes, 0);
        let result = inspect_modules(
            &[executable.clone(), executable],
            Limits {
                max_read_bytes: charge,
                ..Limits::default()
            },
            false,
        );
        assert!(result.errors.is_empty());
        assert_eq!(result.modules.len(), 1);
        assert_eq!(result.totals.objects_attempted, 2);
        assert_eq!(result.totals.objects_inspected, 1);
        assert_eq!(result.totals.read_bytes, charge);
        assert_eq!(inventory_exit(result.capabilities.inventory), 0);
    }

    #[test]
    fn module_object_limit_keeps_already_inspected_independent_file() {
        let result = inspect_modules(
            &[
                PathBuf::from("/bin/true"),
                PathBuf::from("/PRIVATE_CANARY_missing"),
            ],
            Limits {
                max_objects: 1,
                ..Limits::default()
            },
            false,
        );
        assert_eq!(result.modules.len(), 1);
        assert_eq!(result.errors[0].input_index, 1);
        assert_eq!(result.errors[0].reason, GapReason::ObjectLimit);
        assert_eq!(inventory_exit(result.capabilities.inventory), 3);
    }

    #[test]
    fn module_deadline_is_rechecked_after_an_admitted_read_and_parse() {
        let path =
            std::env::temp_dir().join(format!("osslscope-module-deadline-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::copy(&mut File::open("/bin/true").unwrap(), &mut file).unwrap();
        // A valid ELF with a sparse tail keeps the parser result meaningful
        // while making the admitted read/hash outlast this cooperative budget.
        file.set_len(64 * 1024 * 1024).unwrap();
        drop(file);
        let result = inspect_modules(
            &[path.clone()],
            Limits {
                timeout: std::time::Duration::from_millis(100),
                ..Limits::default()
            },
            false,
        );
        std::fs::remove_file(path).unwrap();
        assert!(result.totals.read_bytes > 0, "test must admit a read");
        assert_eq!(
            result.errors.first().map(|error| error.reason),
            Some(GapReason::Deadline)
        );
        assert_eq!(inventory_exit(result.capabilities.inventory), 4);
    }

    #[test]
    fn failed_inspection_counts_once_and_cached_failure_does_not_rehash() {
        let path =
            std::env::temp_dir().join(format!("osslscope-module-nonelf-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"not an ELF").unwrap();
        drop(file);
        let result = inspect_modules(
            &[path.clone(), path.clone()],
            Limits {
                max_read_bytes: 11,
                ..Limits::default()
            },
            false,
        );
        std::fs::remove_file(path).unwrap();
        assert_eq!(result.errors.len(), 2);
        assert!(
            result
                .errors
                .iter()
                .all(|error| error.reason == GapReason::NotElf)
        );
        assert_eq!(result.totals.objects_attempted, 2);
        assert_eq!(result.totals.objects_inspected, 1);
        assert_eq!(result.totals.read_bytes, 11);
    }

    #[test]
    fn inventory_reason_names_state_and_gap_words() {
        assert_eq!(
            super::inventory_exit_reason(super::InventoryState::Complete, &[]),
            None
        );
        let partial = super::inventory_exit_reason(
            super::InventoryState::Partial,
            &[
                super::GapReason::ProcessUnavailable,
                super::GapReason::Deadline,
            ],
        )
        .unwrap();
        assert!(
            partial.contains("partial")
                && partial.contains("process_unavailable")
                && partial.contains("deadline")
                && partial.contains("2 gaps"),
            "partial reason names state, words, count, got: {partial}"
        );
        let unavailable = super::inventory_exit_reason(
            super::InventoryState::Unavailable,
            &[super::GapReason::ProcessUnavailable],
        )
        .unwrap();
        assert!(
            unavailable.contains("unavailable")
                && unavailable.contains("process_unavailable")
                && unavailable.contains("1 gap;"),
            "unavailable reason names state, class, singular count, got: {unavailable}"
        );
    }

    #[test]
    fn shared_identity_line_pins_exact_shape() {
        assert_eq!(
            super::super::identity_totals_line(1, 1),
            "identity: 1 verified, 1 locator-candidate of 2 modules (50% verified)\n"
        );
        assert_eq!(
            super::super::identity_totals_line(0, 0),
            "identity: no modules inventoried\n"
        );
        // The snapshot preamble delegates to the shared helper: one shape.
        assert_eq!(
            super::identity_line(3, 1),
            super::super::identity_totals_line(3, 1)
        );
    }

    #[test]
    fn blindness_predicate_holds_only_on_conclusive_scans() {
        use std::process::Command;
        // A live crypto-free target scanned as-is: its gaps (identity
        // unverified and friends) veto the claim — absence stays
        // inconclusive whenever anything hid a mapping.
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let scanned = super::super::snapshot(&super::super::SnapshotOptions {
            pids: vec![child.id()],
            resolve_paths: false,
            limits: super::super::Limits::default(),
        });
        child.kill().unwrap();
        if scanned.gaps.is_empty() {
            // Verified environment (root): the gap-free no-OpenSSL
            // scan holds directly.
            assert!(
                super::super::snapshot_conclusively_without_openssl(&scanned),
                "gap-free no-OpenSSL scan holds"
            );
        } else {
            assert!(
                !super::super::snapshot_conclusively_without_openssl(&scanned),
                "any gap vetoes the blindness claim"
            );
        }
        // The same snapshot with gaps cleared (as a verified scan
        // would produce): no OpenSSL kinds, nothing hidden — holds.
        let mut cleared = scanned.clone();
        cleared.gaps.clear();
        assert!(
            super::super::snapshot_conclusively_without_openssl(&cleared),
            "gap-free no-OpenSSL scan holds"
        );
        // Module-selector scoping vetoes even the cleared snapshot: a
        // filtered list is not a complete enumeration.
        cleared
            .scope_record
            .modules
            .push("selector-active".to_string());
        assert!(
            !super::super::snapshot_conclusively_without_openssl(&cleared),
            "module selection vetoes the blindness claim"
        );
        // A dead target hides its mappings: inconclusive, never blind.
        let dead = super::super::snapshot(&super::super::SnapshotOptions {
            pids: vec![2147483647],
            resolve_paths: false,
            limits: super::super::Limits::default(),
        });
        assert!(
            !super::super::snapshot_conclusively_without_openssl(&dead),
            "dead-pid gaps veto the blindness claim"
        );
        assert!(
            super::super::blindness_line().contains("blindness: no-mapped-openssl"),
            "shared blindness vocabulary pinned"
        );
    }

    #[test]
    fn preamble_states_blindness_on_conclusive_snapshot() {
        // Render presence for the conclusive case (no deterministic
        // gap-free scan exists unprivileged, so the cleared live
        // snapshot stands in for a verified one).
        use std::process::Command;
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut scanned = super::super::snapshot(&super::super::SnapshotOptions {
            pids: vec![child.id()],
            resolve_paths: false,
            limits: super::super::Limits::default(),
        });
        child.kill().unwrap();
        scanned.gaps.clear();
        let preamble = scanned.human_preamble();
        assert!(preamble.conclusively_without_openssl);
        let mut buf = Vec::new();
        super::render(&scanned, false, &mut buf, Some(&preamble), &[]).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("blindness: no-mapped-openssl"),
            "preamble states the boundary, got head: {}",
            out.lines().take(6).collect::<Vec<_>>().join("\n")
        );
    }
}
