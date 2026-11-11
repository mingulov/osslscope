// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive inventory commands. User supplied strings never enter diagnostics.
use super::{
    Capabilities, Gap, GapReason, IdentityAvailability, InventoryState, Limits, ModuleInfo,
    ObservationState, ProcessRecord, Snapshot, SnapshotOptions, WorkTotals, elf, snapshot,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal as _, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const HELP: &str = "usage: osslscope scan [--pid PID ...] [--cgroup PATH] [--module PATH ...] [--watch [--interval S] [--duration S]] [--json] [--resolve-paths] [-v]\n       osslscope inspect --pid PID [--json] [--resolve-paths] [-v]\n       osslscope inspect --module PATH [--module PATH ...] [--json] [--resolve-paths] [-v]\nAdd --observe-crypto to scan --watch for automatic per-process crypto observations.\n--resolve-paths renders verified host paths on TTY-attached human rows (default off; --json acquires machine path evidence without the flag; never in diagnostics).\n-v/--verbose (repeatable, -vv = 2) raises human detail only: -v adds grouped gaps, per-module exports, and full per-process state; -vv adds per-object gap records and safe counters. Default human output is quiet; JSON output is complete at every level.\nPassive file-backed inventory; ELF exports and mappings do not prove activation or execution.\nProvider activation/interfaces remain unknown; execution is not_observed.\n";
const MEANING: &str = "Passive inventory: ELF exports and mappings do not prove activation or execution.\nProvider activation/interfaces: unknown; execution: not_observed.\n";
/// One-line kind legend (v0.6.0 P0-5): decodes every `ObjectKind`
/// word without source. Glosses mirror `elf.rs` classification
/// exactly (recognized dynamic code exports; `OSSL_PROVIDER_init`;
/// known `libcrypto`/`libssl` SONAME need or recognized API
/// import); `other` is counted per process, never listed.
/// Single source for human snapshots and `--help`.
const LEGEND: &str = "kinds: openssl_compatible=<exports-recognized-api> provider_module=<exports-ossl_provider_init> openssl_consumer=<depends-or-imports-openssl> other=<counted-not-listed>\n";
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
    /// Human detail level: `-v`/`--verbose` repeatable, `-vv` = 2,
    /// clamped at 2 (default 0 is quiet). Gates detail volume
    /// only — exits, stderr, counts, and JSON bytes are identical
    /// at every level. v0.6.0 P0-3: report/check/service human
    /// redesign stays P1; verbosity applies to
    /// scan/inspect/provider/crypto-watch/doctor routes.
    pub(crate) verbosity: u8,
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
        verbosity: 0,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" if !options.json => options.json = true,
            "--resolve-paths" if !options.resolve_paths => options.resolve_paths = true,
            // Repeatable, clamped at 2 after the loop. `-q`/`--quiet`
            // stay unknown (exit 2, empty stdout): the default is
            // already quiet, so no quiet flag exists.
            "-v" | "--verbose" => {
                options.verbosity = options.verbosity.saturating_add(1);
            }
            "-vv" => options.verbosity = 2,
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
    options.verbosity = options.verbosity.min(2);
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
/// Stderr privilege hint (v0.6.0 P0-6): `Some` iff at least one gap
/// carries errno EPERM/EACCES from an actually refused open — the
/// only trigger. Bare gaps (`too_large`, `changed`, limits, dead
/// pids) and non-permission errnos never fire it, and a root run
/// gets the hint too when root is actually denied. The counts state
/// the unverified portion: `u` = locator-candidate modules + gaps
/// naming a pid, `t` = all modules + all gaps, both from the
/// finished snapshot with no extra IO (`u <= t` always; firing
/// implies `u >= 1` since every denial site names its pid). The
/// word is EACCES when any denial is EACCES, else EPERM. Names
/// root-as-supported (D5) and points at `usage.md#privilege`;
/// capability recipes stay best-effort, never a universal set.
/// Verbosity-independent; the caller emits it once per invocation
/// on stderr only.
pub(crate) fn privilege_hint(snapshot: &Snapshot) -> Option<String> {
    let denied = snapshot.gaps.iter().any(|gap| {
        gap.errno
            .is_some_and(|e| e == libc::EPERM || e == libc::EACCES)
    });
    if !denied {
        return None;
    }
    let word = if snapshot
        .gaps
        .iter()
        .any(|gap| gap.errno == Some(libc::EACCES))
    {
        "EACCES"
    } else {
        "EPERM"
    };
    let (_, locator) = snapshot.identity_counts();
    let modules: usize = snapshot
        .processes
        .iter()
        .map(|process| process.modules.len())
        .sum();
    let named = snapshot.gaps.iter().filter(|gap| gap.pid.is_some()).count();
    let unverified = locator + named;
    let total = modules + snapshot.gaps.len();
    Some(format!(
        "osslscope discovery: {unverified} of {total} modules unverified: permission denied ({word}); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege"
    ))
}
/// Human `comm=` value for one verdict line: the sampled name
/// sanitized at this human boundary, `-` whenever the sample is
/// anything but a present `Available` value. Null/missing renders
/// the placeholder, never crashes.
fn human_comm(process: &ProcessRecord) -> String {
    if process.comm_status == IdentityAvailability::Available {
        let shown = process
            .comm
            .as_deref()
            .map(crate::report::safe_display)
            .unwrap_or_default();
        if !shown.is_empty() {
            return shown;
        }
    }
    "-".to_string()
}

/// Human `exe=` value for one verdict line: the last two components
/// of the sampled spelling, sanitized via
/// [`crate::report::safe_display`] at this human boundary (`exe` is
/// verbatim-lossy in JSON — machine T4 parked minor). `-` when the
/// sample never observed anything (`Unreadable`); `unavailable`
/// when a sample existed but cannot pin a spelling (`Changed`,
/// `TooLong` — a truncated tail would mislabel — or a missing value
/// despite `Available`). Null/missing renders a placeholder, never
/// crashes.
fn human_exe(process: &ProcessRecord) -> String {
    if process.exe_status == IdentityAvailability::Available {
        if let Some(exe) = process.exe.as_deref() {
            let safe = crate::report::safe_display(exe);
            let tail: Vec<&str> = safe
                .split('/')
                .filter(|c| !c.is_empty())
                .rev()
                .take(2)
                .collect();
            let short = tail.into_iter().rev().collect::<Vec<_>>().join("/");
            if !short.is_empty() {
                return short;
            }
        }
        return "unavailable".to_string();
    }
    match process.exe_status {
        IdentityAvailability::Unreadable => "-".to_string(),
        _ => "unavailable".to_string(),
    }
}

/// Per-process verdict line: `pid= comm= exe= modules= status=`.
/// `status` is `complete` iff no gap names this pid (unnamed,
/// process-wide gaps do not mark any single process partial).
/// When `modules` is empty the line carries the firefox-style
/// Other disclosure (`0 OpenSSL modules, N other objects
/// scanned`, N = successfully classified Others; failures ride
/// the gaps line). At `-v` and above the line extends with full
/// per-process state (`starttime= namespaces=
/// provider_activation= provider_interfaces= execution=`);
/// level 0 stays a strict prefix.
fn verdict_line(process: &ProcessRecord, gaps: &[Gap], verbosity: u8) -> String {
    let status = if gaps.iter().any(|g| g.pid == Some(process.pid)) {
        "partial"
    } else {
        "complete"
    };
    let mut line = format!(
        "pid={} comm={} exe={} modules={} status={}",
        process.pid,
        human_comm(process),
        human_exe(process),
        process.modules.len(),
        status
    );
    if process.modules.is_empty() {
        line.push_str(&format!(
            " (0 OpenSSL modules, {} other objects scanned)",
            process.other_objects.verified + process.other_objects.candidate
        ));
    }
    if verbosity >= 1 {
        line.push_str(&format!(
            " starttime={} namespaces={} provider_activation={} provider_interfaces={} execution={}",
            process.starttime,
            super::human_namespaces(&process.namespaces),
            process.provider_activation.word(),
            process.provider_interfaces.word(),
            process.execution.word()
        ));
    }
    line
}

/// Exact per-reason counts line (`gaps:` for snapshots, `errors:`
/// for operator-supplied module lists): reasons sorted by word,
/// counters exact. The `-v` rerun hint rides the snapshot line only
/// (Task 2 lands per-object gap detail there; the module route has
/// no such detail planned, so its line stays hint-free and honest).
fn counts_line(label: &str, reasons: impl Iterator<Item = GapReason>, rerun_hint: bool) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut total = 0usize;
    for reason in reasons {
        *counts.entry(reason.word()).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return format!("{label}: 0\n");
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(word, count)| format!("{word}={count}"))
        .collect();
    if rerun_hint {
        format!(
            "{label}: {total} ({}; rerun with -v for per-object detail)\n",
            parts.join(" ")
        )
    } else {
        format!("{label}: {total} ({})\n", parts.join(" "))
    }
}

/// One-line default meaning per gap reason (v0.6.0 D6: the 128 MiB
/// cap stays; default output must explain the omitted evidence).
/// Each line states what was not observed and what stays unknown;
/// the full runbook stays P1. Rendered by
/// [`gap_meanings_block`] beside the per-reason counts.
pub(crate) fn gap_meaning(reason: GapReason) -> &'static str {
    match reason {
        GapReason::Unavailable => {
            "unavailable: a file needed for inventory could not be opened or read; what it held is unknown"
        }
        GapReason::NonRegular => {
            "non_regular: path is not a regular file, so it was never parsed; its interfaces are unknown"
        }
        GapReason::TooLarge => {
            "too_large: file over the 128 MiB read cap was not read; its kind, sha256, and version are unknown"
        }
        GapReason::NotElf => {
            "not_elf: file lacks ELF magic, so it was never classified; its interfaces are unknown"
        }
        GapReason::MalformedElf => {
            "malformed_elf: ELF headers failed to parse; its kind, sha256, and version are unknown"
        }
        GapReason::Changed => {
            "changed: file or process changed mid-sample, so the stale reading was discarded"
        }
        GapReason::UnsupportedArchitecture => {
            "unsupported_architecture: object targets an architecture this observer cannot parse; its interfaces are unknown"
        }
        GapReason::ProcessUnavailable => {
            "process_unavailable: process exited or its /proc entries were unreadable; its inventory is unknown"
        }
        GapReason::IdentityUnverified => {
            "identity_unverified: candidate file metadata is unproven as the mapped backing; the mapping's true kind is unknown"
        }
        GapReason::BackingUnavailable => {
            "backing_unavailable: executable backing could not be opened or its identity mismatched; the mapping's bytes are unknown"
        }
        GapReason::ReadLimit => {
            "read_limit: the 1 GiB shared read budget ran out; uncharged files were never read"
        }
        GapReason::ProcessLimit => {
            "process_limit: the 4096-process cap was reached; further processes were not inventoried"
        }
        GapReason::ObjectLimit => {
            "object_limit: the object admission cap was reached; further objects were not inspected"
        }
        GapReason::MalformedMaps => {
            "malformed_maps: a /proc/PID/maps line failed to parse; that mapping's inventory is unknown"
        }
        GapReason::Deadline => {
            "deadline: the 30-second cooperative deadline expired; remaining work was abandoned"
        }
        GapReason::UnsupportedCgroup => {
            "unsupported_cgroup: cgroup is not a traversable domain cgroup; its subtree was not selected"
        }
        GapReason::CgroupUnavailable => {
            "cgroup_unavailable: cgroup directory could not be opened or pinned; its members are unknown"
        }
        GapReason::CgroupLimit => {
            "cgroup_limit: cgroup traversal hit its directory or membership cap; the uncertain subtree was omitted"
        }
        GapReason::MembershipUnknown => {
            "membership_unknown: cgroup membership could not be sampled; which processes belong is unknown"
        }
        GapReason::NamespaceUnavailable => {
            "namespace_unavailable: namespace identity could not be read; process coordinates are unverified"
        }
    }
}

/// Default-verbosity gap explanations: one [`gap_meaning`] line
/// per distinct counted reason, nested under the counts line.
/// Meanings sort by word (each starts with its word), matching
/// [`counts_line`] order; empty when there is nothing to explain.
/// Rendered with the counts block at every human level — counts
/// are verbosity-independent (H2), and their explanation rides
/// along rather than vanishing under `-v`.
fn gap_meanings_block(reasons: impl Iterator<Item = GapReason>) -> String {
    let mut meanings: BTreeSet<&str> = BTreeSet::new();
    for reason in reasons {
        meanings.insert(gap_meaning(reason));
    }
    let mut out = String::new();
    for meaning in meanings {
        out.push_str("  ");
        out.push_str(meaning);
        out.push('\n');
    }
    out
}

/// Human snapshot render (v0.6.0 P0-3): MEANING, the kind
/// legend, per-process verdict lines with their module rows,
/// identity totals, exact per-reason gap counts each with its
/// one-line meaning (plus the blindness line when conclusive).
/// Never emits JSON bytes.
/// Verbosity gates detail volume only (0 = counts line; 1 = full
/// gap groups, `exports=[...]` per module row, and full
/// per-process state; 2 = per-object gap records and safe
/// counters); exits, stderr, counts, and hashes (short at every
/// level) are identical throughout.
pub(crate) fn human_snapshot(
    writer: &mut impl Write,
    snapshot: &Snapshot,
    paths: &super::resolve::TerminalPathWriter,
    verbosity: u8,
) -> io::Result<()> {
    writer.write_all(MEANING.as_bytes())?;
    writer.write_all(LEGEND.as_bytes())?;
    human_snapshot_body(writer, snapshot, paths, verbosity, None)?;
    if super::snapshot_conclusively_without_openssl(snapshot) {
        writer.write_all(super::blindness_line().as_bytes())?;
    }
    writer.flush()
}

/// The state block of [`human_snapshot`] without MEANING or the
/// blindness line (both stay caller-owned: streaming callers
/// print them once per run, never per sample — H1). `only`
/// restricts the verdict+row section to changed (pid,
/// starttime) processes; totals, counts, groups, records, and
/// counters always cover the whole snapshot (H2: counts are
/// never filtered by a delta). Bytes for `only = None` are
/// exactly [`human_snapshot`] minus its preamble, blindness
/// line, and flush.
pub(crate) fn human_snapshot_body(
    writer: &mut impl Write,
    snapshot: &Snapshot,
    paths: &super::resolve::TerminalPathWriter,
    verbosity: u8,
    only: Option<&BTreeSet<(u32, u64)>>,
) -> io::Result<()> {
    // Clamped here so a future caller can never observe an
    // unclamped level.
    let level = verbosity.min(2);
    for process in &snapshot.processes {
        if only.is_some_and(|set| !set.contains(&(process.pid, process.starttime))) {
            continue;
        }
        writeln!(writer, "{}", verdict_line(process, &snapshot.gaps, level))?;
        let rows = paths.object_rows(std::slice::from_ref(process));
        // `object_rows` builds exactly one row per module in order;
        // the zip below appends each module's own exports.
        debug_assert_eq!(rows.len(), process.modules.len());
        if level >= 1 {
            for (row, module) in rows.iter().zip(process.modules.iter()) {
                writeln!(
                    writer,
                    "{row} {}",
                    super::human_exports(&module.info.exports)
                )?;
            }
        } else {
            for row in &rows {
                writeln!(writer, "{row}")?;
            }
        }
    }
    let (verified, locator) = snapshot.identity_counts();
    writer.write_all(super::identity_totals_line(verified, locator).as_bytes())?;
    writer
        .write_all(counts_line("gaps", snapshot.gaps.iter().map(|g| g.reason), true).as_bytes())?;
    writer.write_all(gap_meanings_block(snapshot.gaps.iter().map(|g| g.reason)).as_bytes())?;
    if level >= 1 {
        let block = super::gap_groups_block(
            snapshot
                .gaps
                .iter()
                .map(|g| (g.reason.word(), g.device, g.pid)),
            "",
        );
        writer.write_all(block.as_bytes())?;
    }
    if level >= 2 {
        for gap in &snapshot.gaps {
            writeln!(
                writer,
                "gap pid={} device={} reason={} errno={}",
                gap.pid.map_or("-".to_string(), |p| p.to_string()),
                gap.device.map_or("-".to_string(), |d| d.to_string()),
                gap.reason.word(),
                gap.errno.map_or("-".to_string(), |e| e.to_string())
            )?;
        }
        writeln!(
            writer,
            "counters: read_bytes={} objects_inspected={}",
            snapshot.totals.read_bytes, snapshot.totals.objects_inspected
        )?;
    }
    Ok(())
}

/// Human render for operator-supplied module lists
/// (`inspect --module`, v0.6.0 P0-3): MEANING + one row per module
/// + exact per-reason error counts. Never emits JSON bytes.
fn human_modules(
    writer: &mut impl Write,
    inventory: &ModuleInventory,
    paths: &super::resolve::TerminalPathWriter,
) -> io::Result<()> {
    writer.write_all(MEANING.as_bytes())?;
    for row in paths.module_rows(&inventory.modules) {
        writeln!(writer, "{row}")?;
    }
    writer.write_all(
        counts_line("errors", inventory.errors.iter().map(|e| e.reason), false).as_bytes(),
    )?;
    writer.write_all(gap_meanings_block(inventory.errors.iter().map(|e| e.reason)).as_bytes())?;
    writer.flush()
}

/// Pure machine render: ONLY the JSON document on stdout, no
/// preamble, no rows (v0.6.0 P0-3 stdout split).
fn render_json(value: &impl Serialize, writer: &mut impl Write) -> io::Result<()> {
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
            .and_then(|()| output.write_all(LEGEND.as_bytes()))
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
        // Read before the Selection moves below consume the vectors.
        let verbosity = options.verbosity;
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
                verbosity,
            )
            .map(|outcome| {
                if let Some(line) = super::watch::exit_reason(&outcome) {
                    crate::report::err_line(&line);
                }
                // P0-6: the run-retained hint (if any tick was
                // denied), once per run — never per tick.
                if let Some(hint) = outcome.privilege_hint.as_deref() {
                    crate::report::err_line(hint);
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
            let writer = super::resolve::TerminalPathWriter::new(
                render_paths,
                output.is_terminal(),
                &result.resolve,
            );
            // v0.6.0 P0-3 stdout split: rows by default, JSON opt-in.
            let rendered = if options.json {
                render_json(&result, &mut output)
            } else {
                human_snapshot(&mut output, &result, &writer, verbosity)
            };
            rendered.map(|()| {
                let reasons: Vec<GapReason> = result.gaps.iter().map(|g| g.reason).collect();
                if let Some(line) = inventory_exit_reason(result.capabilities.inventory, &reasons) {
                    crate::report::err_line(&line);
                }
                if let Some(hint) = privilege_hint(&result) {
                    crate::report::err_line(&hint);
                }
                result.exit_code()
            })
        } else if options.modules.is_empty() {
            let result = snapshot(&SnapshotOptions {
                pids: options.pids,
                limits: Limits::default(),
                resolve_paths: acquire,
            });
            let writer = super::resolve::TerminalPathWriter::new(
                render_paths,
                output.is_terminal(),
                &result.resolve,
            );
            // v0.6.0 P0-3 stdout split: rows by default, JSON opt-in.
            let rendered = if options.json {
                render_json(&result, &mut output)
            } else {
                human_snapshot(&mut output, &result, &writer, verbosity)
            };
            rendered.map(|()| {
                let reasons: Vec<GapReason> = result.gaps.iter().map(|g| g.reason).collect();
                if let Some(line) = inventory_exit_reason(result.capabilities.inventory, &reasons) {
                    crate::report::err_line(&line);
                }
                if let Some(hint) = privilege_hint(&result) {
                    crate::report::err_line(&hint);
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
            // v0.6.0 P0-3 stdout split: rows by default, JSON opt-in.
            // The --module route stays flat at every verbosity (Task 1
            // decision: no per-object detail planned there).
            let rendered = if options.json {
                render_json(&result, &mut output)
            } else {
                human_modules(&mut output, &result, &writer)
            };
            rendered.map(|()| {
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
        Api, Architecture, CaptureInterval, FileVersionStatus, Gap, GapReason,
        IdentityAvailability, IdentityStatus, ModuleInfo, ModuleRecord, NamespaceId, NamespaceIds,
        ObjectKind, OtherCounts, ProcessRecord, Scope, ScopeRecord, Snapshot, SnapshotMode,
        coalesce_gaps,
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
                other_objects: OtherCounts::default(),
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
        let paths = super::super::resolve::TerminalPathWriter::new(false, false, &snap.resolve);
        let mut buf = Vec::new();
        super::human_snapshot(&mut buf, &snap, &paths, 0).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // v0.6.0 P0-3 rows-only human bytes: MEANING + kind
        // legend + verdict + module rows + identity totals + exact
        // gap counts, no JSON.
        assert!(out.contains("Passive inventory:"), "{out}");
        assert!(
            out.contains("pid=1 comm=- exe=- modules=2 status=complete"),
            "{out}"
        );
        assert!(
            out.contains("identity: 1 verified, 1 locator-candidate of 2 modules (50% verified)\n"),
            "{out}"
        );
        assert!(out.contains("gaps: 0\n"), "{out}");
        assert!(!out.contains("\"schema_version\""), "{out}");
        assert!(!out.contains("gaps ("), "{out}");
        // JSON mode carries ONLY the document: no preamble at all.
        let mut buf = Vec::new();
        super::render_json(&snap, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("identity: "), "{out}");
        assert!(!out.contains("Passive inventory"), "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["schema_version"], "osslscope.discovery.v1");
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
    fn v060_default_gap_meanings_explain_omitted_evidence() {
        assert_eq!(
            super::gap_meaning(GapReason::TooLarge),
            "too_large: file over the 128 MiB read cap was not read; its kind, sha256, and version are unknown"
        );
        // Every reason has a one-line default meaning (full runbook stays P1).
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
            assert!(!super::gap_meaning(reason).is_empty(), "{reason:?}");
        }
    }

    #[test]
    fn object_kind_words_match_json() {
        // Every word mirrors the serde snake_case label exactly.
        for kind in [
            ObjectKind::OpenSslCompatible,
            ObjectKind::ProviderModule,
            ObjectKind::OpenSslConsumer,
            ObjectKind::Other,
        ] {
            let json = serde_json::to_value(kind).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(kind.word().into()),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn human_verdict_pins_identity_placeholders_and_partial() {
        // exe shortens to its last two components, sanitized; a gap
        // naming the pid marks it partial.
        let mut snap = snapshot_with(Vec::new());
        snap.processes[0].comm = Some("py\x1bthon".to_string());
        snap.processes[0].comm_status = IdentityAvailability::Available;
        snap.processes[0].exe = Some("/usr/bin/python3".to_string());
        snap.processes[0].exe_status = IdentityAvailability::Available;
        assert_eq!(
            super::verdict_line(&snap.processes[0], &snap.gaps, 0),
            "pid=1 comm=py?thon exe=bin/python3 modules=0 status=complete (0 OpenSSL modules, 0 other objects scanned)"
        );
        snap.gaps.push(Gap {
            pid: Some(1),
            device: None,
            inode: None,
            reason: GapReason::BackingUnavailable,
            errno: None,
            actor_euid: None,
        });
        assert!(
            super::verdict_line(&snap.processes[0], &snap.gaps, 0).contains("status=partial"),
            "gap naming the pid marks it partial"
        );
    }

    #[test]
    fn human_snapshot_carries_kind_legend_and_other_disclosure() {
        // P0-5: the legend line decodes every kind word; an empty
        // `modules` verdict discloses classified Others (N =
        // verified + candidate — `failed` rides the gaps line);
        // a non-empty verdict carries no disclosure.
        let mut snap = snapshot_with(Vec::new());
        snap.processes[0].other_objects = OtherCounts {
            verified: 4,
            candidate: 1,
            failed: 2,
        };
        let paths = super::super::resolve::TerminalPathWriter::new(false, false, &snap.resolve);
        let mut buf = Vec::new();
        super::human_snapshot(&mut buf, &snap, &paths, 0).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains(super::LEGEND), "{out}");
        assert!(
            out.contains("(0 OpenSSL modules, 5 other objects scanned)"),
            "{out}"
        );
        let listed = snapshot_with(vec![module_with(IdentityStatus::Verified)]);
        let paths = super::super::resolve::TerminalPathWriter::new(false, false, &listed.resolve);
        let mut buf = Vec::new();
        super::human_snapshot(&mut buf, &listed, &paths, 0).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains(super::LEGEND), "{out}");
        assert!(!out.contains("other objects scanned"), "{out}");
    }

    #[test]
    fn other_counts_default_and_always_serialized() {
        // Old documents without the key still parse (zeros); every
        // serialization carries it; unknown keys still rejected.
        let legacy: ProcessRecord = serde_json::from_str(
            r#"{"interval":{"started_unix_ms":null,"finished_unix_ms":null,"elapsed_ns":0},"namespaces":{"pid":null,"mount":null},"pid":1,"starttime":7,"modules":[],"provider_activation":"unknown","provider_interfaces":"unknown","execution":"not_observed"}"#,
        )
        .unwrap();
        assert_eq!(legacy.other_objects, OtherCounts::default());
        let value = serde_json::to_value(&legacy).unwrap();
        assert_eq!(
            value["other_objects"],
            serde_json::json!({"verified": 0, "candidate": 0, "failed": 0})
        );
        assert!(
            serde_json::from_str::<OtherCounts>(
                r#"{"verified":1,"candidate":0,"failed":0,"bogus":1}"#
            )
            .is_err()
        );
    }

    #[test]
    fn human_exe_maps_every_status_to_placeholder_or_short() {
        let mut snap = snapshot_with(Vec::new());
        let process = &mut snap.processes[0];
        // Unreadable never observed anything: bare dash.
        process.exe = None;
        process.exe_status = IdentityAvailability::Unreadable;
        assert_eq!(super::human_exe(process), "-");
        // Changed/TooLong observed something unpinnable: unavailable
        // (a truncated tail would mislabel, so TooLong never shorts).
        process.exe_status = IdentityAvailability::Changed;
        assert_eq!(super::human_exe(process), "unavailable");
        process.exe = Some("/usr/bin/python3".to_string());
        process.exe_status = IdentityAvailability::TooLong;
        assert_eq!(super::human_exe(process), "unavailable");
        // Available-but-missing is corrupt input: placeholder, no crash.
        process.exe = None;
        process.exe_status = IdentityAvailability::Available;
        assert_eq!(super::human_exe(process), "unavailable");
        // Available shortens + sanitizes at the human boundary.
        process.exe = Some("/opt\x07/x/y".to_string());
        assert_eq!(super::human_exe(process), "x/y");
        process.exe = Some("/sleep".to_string());
        assert_eq!(super::human_exe(process), "sleep");
        // comm: anything but a present Available value is a dash.
        process.comm = Some("x".to_string());
        process.comm_status = IdentityAvailability::TooLong;
        assert_eq!(super::human_comm(process), "-");
        process.comm = None;
        process.comm_status = IdentityAvailability::Available;
        assert_eq!(super::human_comm(process), "-");
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
        let paths = super::super::resolve::TerminalPathWriter::new(false, false, &snap.resolve);
        let mut buf = Vec::new();
        super::human_snapshot(&mut buf, &snap, &paths, 0).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // v0.6.0 P0-3: exact per-reason counts on one line (groups
        // deferred to -v); counters exact.
        assert!(
            out.contains("gaps: 2 (too_large=2; rerun with -v for per-object detail)\n"),
            "{out}"
        );
        // v0.6.0 D6: each counted reason carries its one-line
        // meaning beside the counts at default verbosity.
        assert!(
            out.contains("  too_large: file over the 128 MiB read cap was not read; its kind, sha256, and version are unknown\n"),
            "{out}"
        );
        assert!(!out.contains("gaps ("), "{out}");
        // The verdict names only gaps for its own pid: pid 1 stays
        // complete while pid 7's gaps count above.
        assert!(out.contains("status=complete"), "{out}");
        // JSON mode carries the raw array, never the counts line.
        let mut buf = Vec::new();
        super::render_json(&snap, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("gaps:"), "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["gaps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn human_modules_renders_error_meanings() {
        // v0.6.0 D6: the inspect --module errors line carries the
        // same one-line meanings as the snapshot gaps line.
        let result = super::inspect_modules(
            &[PathBuf::from("/PRIVATE_CANARY_missing")],
            Limits::default(),
            false,
        );
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].reason, GapReason::Unavailable);
        let paths = super::super::resolve::TerminalPathWriter::new(false, false, &result.resolve);
        let mut buf = Vec::new();
        super::human_modules(&mut buf, &result, &paths).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("errors: 1 (unavailable=1)\n"), "{out}");
        assert!(
            out.contains("  unavailable: a file needed for inventory could not be opened or read; what it held is unknown\n"),
            "{out}"
        );
    }

    #[test]
    fn verbosity_parses_repeatable_and_clamps_at_two() {
        let parse = |command: &str, flags: &[&str]| {
            super::parse_inner(
                command,
                &flags.iter().map(|f| f.to_string()).collect::<Vec<_>>(),
                false,
            )
        };
        assert_eq!(parse("scan", &[]).unwrap().verbosity, 0);
        assert_eq!(parse("scan", &["-v"]).unwrap().verbosity, 1);
        assert_eq!(parse("scan", &["--verbose"]).unwrap().verbosity, 1);
        assert_eq!(parse("scan", &["-v", "-v"]).unwrap().verbosity, 2);
        assert_eq!(parse("scan", &["-vv"]).unwrap().verbosity, 2);
        assert_eq!(parse("scan", &["-vv", "-v"]).unwrap().verbosity, 2);
        assert_eq!(parse("scan", &["-v", "-v", "-v"]).unwrap().verbosity, 2);
        assert_eq!(
            parse("inspect", &["--pid", "1", "-vv"]).unwrap().verbosity,
            2
        );
        // No quiet flag exists: the default is already quiet.
        assert!(parse("scan", &["-q"]).is_err());
        assert!(parse("scan", &["--quiet"]).is_err());
        assert!(parse("scan", &["-vvv"]).is_err());
    }

    #[test]
    fn observation_state_words_match_json() {
        for state in [
            super::super::ObservationState::Unknown,
            super::super::ObservationState::NotObserved,
        ] {
            let json = serde_json::to_value(state).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(state.word().into()),
                "{state:?}"
            );
        }
    }

    #[test]
    fn human_namespaces_and_exports_fragments() {
        assert_eq!(
            super::super::human_namespaces(&NamespaceIds::default()),
            "pid=-,mount=-"
        );
        assert_eq!(
            super::super::human_namespaces(&NamespaceIds {
                pid: Some(NamespaceId {
                    device: 5,
                    inode: 123
                }),
                mount: None,
            }),
            "pid=5:123,mount=-"
        );
        assert_eq!(super::super::human_exports(&[]), "exports=[]");
        assert_eq!(
            super::super::human_exports(&[Api::OsslProviderInit, Api::EvpDigestUpdate]),
            "exports=[ossl_provider_init, evp_digest_update]"
        );
    }

    #[test]
    fn human_snapshot_verbosity_levels_add_groups_state_records_counters() {
        let mut module = module_with(IdentityStatus::Verified);
        module.info.sha256 = "a".repeat(64);
        module.info.exports = vec![Api::OsslProviderInit, Api::EvpDigestUpdate];
        let mut snap = snapshot_with(vec![module]);
        snap.processes[0].namespaces.pid = Some(NamespaceId {
            device: 5,
            inode: 123,
        });
        snap.totals.read_bytes = 4096;
        snap.totals.objects_inspected = 7;
        snap.gaps = vec![
            Gap {
                pid: Some(7),
                device: Some(1),
                inode: Some(10),
                reason: GapReason::TooLarge,
                errno: Some(libc::EPERM),
                actor_euid: Some(1001),
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
        let render = |verbosity: u8| {
            let paths = super::super::resolve::TerminalPathWriter::new(false, false, &snap.resolve);
            let mut buf = Vec::new();
            super::human_snapshot(&mut buf, &snap, &paths, verbosity).unwrap();
            String::from_utf8(buf).unwrap()
        };
        let counts = "gaps: 2 (deadline=1 too_large=1; rerun with -v for per-object detail)\n";
        let l0 = render(0);
        assert!(l0.contains(counts), "{l0}");
        assert!(!l0.contains("exports="), "{l0}");
        assert!(!l0.contains("gaps ("), "{l0}");
        assert!(!l0.contains("starttime="), "{l0}");
        assert!(!l0.contains("gap pid="), "{l0}");
        assert!(!l0.contains("counters:"), "{l0}");
        let l1 = render(1);
        assert!(l1.contains(counts), "{l1}");
        assert!(
            l1.contains("exports=[ossl_provider_init, evp_digest_update]"),
            "{l1}"
        );
        assert!(l1.contains("gaps (2 total in 2 groups):"), "{l1}");
        assert!(
            l1.contains("starttime=0 namespaces=pid=5:123,mount=-"),
            "{l1}"
        );
        assert!(
            l1.contains(
                "provider_activation=unknown provider_interfaces=unknown execution=not_observed"
            ),
            "{l1}"
        );
        assert!(!l1.contains("gap pid="), "{l1}");
        assert!(!l1.contains("counters:"), "{l1}");
        let l2 = render(2);
        assert!(l2.contains(counts), "{l2}");
        assert!(
            l2.contains("gap pid=7 device=1 reason=too_large errno=1"),
            "{l2}"
        );
        assert!(
            l2.contains("gap pid=- device=- reason=deadline errno=-"),
            "{l2}"
        );
        assert!(
            l2.contains("counters: read_bytes=4096 objects_inspected=7"),
            "{l2}"
        );
        // Unclamped callers still render level 2; short hashes at
        // every level (the 64-hex fixture never leaks in full).
        assert_eq!(render(9), l2);
        for out in [&l0, &l1, &l2] {
            assert!(!out.contains(&"a".repeat(64)), "{out}");
            assert!(out.contains("sha256=aaaaaaaaaaaa"), "{out}");
        }
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
    fn privilege_hint_fires_only_on_errno_proven_denial() {
        // P0-6 trigger: actual EPERM/EACCES only. Clean snapshots,
        // bare gaps (too_large, changed, process_unavailable,
        // limits), and non-permission errnos never fire it.
        let gap = |reason, errno| Gap {
            pid: Some(7),
            device: Some(1),
            inode: Some(10),
            reason,
            errno,
            actor_euid: errno.map(|_| 1001),
        };
        let mut snap = snapshot_with(vec![module_with(IdentityStatus::Verified)]);
        assert_eq!(super::privilege_hint(&snap), None);
        for (reason, errno) in [
            (GapReason::TooLarge, None),
            (GapReason::Changed, None),
            (GapReason::ProcessUnavailable, None),
            (GapReason::ReadLimit, None),
            (GapReason::BackingUnavailable, Some(libc::ENOENT)),
        ] {
            snap.gaps = vec![gap(reason, errno)];
            assert_eq!(
                super::privilege_hint(&snap),
                None,
                "fired for {reason:?}/{errno:?}"
            );
        }
        // Denied: u = locator-candidate modules (1) + pid-naming
        // gaps (2) = 3; t = modules (2) + gaps (3) = 5. The
        // pid-less limit gap counts in t but not u; EACCES wins
        // the word when both denials are present.
        let mut denied = snapshot_with(vec![
            module_with(IdentityStatus::Verified),
            module_with(IdentityStatus::LocatorCandidate),
        ]);
        denied.gaps = vec![
            gap(GapReason::IdentityUnverified, Some(libc::EPERM)),
            gap(GapReason::ProcessUnavailable, Some(libc::EACCES)),
            Gap {
                pid: None,
                device: None,
                inode: None,
                reason: GapReason::ReadLimit,
                errno: None,
                actor_euid: None,
            },
        ];
        assert_eq!(
            super::privilege_hint(&denied).as_deref(),
            Some(
                "osslscope discovery: 3 of 5 modules unverified: permission denied (EACCES); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege"
            )
        );
        // EPERM alone names EPERM: u = 0 + 1 = 1, t = 0 + 1 = 1.
        let mut eperm = snapshot_with(Vec::new());
        eperm.gaps = vec![gap(GapReason::BackingUnavailable, Some(libc::EPERM))];
        assert_eq!(
            super::privilege_hint(&eperm).as_deref(),
            Some(
                "osslscope discovery: 1 of 1 modules unverified: permission denied (EPERM); re-run as root for a complete inventory (supported path); capability recipes are best-effort, see usage.md#privilege"
            )
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
        assert!(super::super::snapshot_conclusively_without_openssl(
            &scanned
        ));
        let paths = super::super::resolve::TerminalPathWriter::new(false, false, &scanned.resolve);
        let mut buf = Vec::new();
        super::human_snapshot(&mut buf, &scanned, &paths, 0).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("blindness: no-mapped-openssl"),
            "preamble states the boundary, got head: {}",
            out.lines().take(6).collect::<Vec<_>>().join("\n")
        );
    }
}
