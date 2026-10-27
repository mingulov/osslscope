// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive inventory commands. User supplied strings never enter diagnostics.
use super::{
    Capabilities, GapReason, InventoryState, Limits, ModuleInfo, ObservationState, SnapshotOptions,
    WorkTotals, elf, snapshot,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const HELP: &str = "usage: osslscope scan [--pid PID ...] [--cgroup PATH] [--module PATH ...] [--watch [--interval S] [--duration S]] [--json]\n       osslscope inspect --pid PID [--json]\n       osslscope inspect --module PATH [--module PATH ...] [--json]\nPassive file-backed inventory; ELF exports and mappings do not prove activation or execution.\nProvider activation/interfaces remain unknown; execution is not_observed.\n";
const MEANING: &str = "Passive inventory: ELF exports and mappings do not prove activation or execution.\nProvider activation/interfaces: unknown; execution: not_observed.\n";

struct Options {
    pids: Vec<u32>,
    modules: Vec<PathBuf>,
    cgroup: Option<PathBuf>,
    json: bool,
    watch: bool,
    interval: Option<Duration>,
    duration: Option<Duration>,
}
fn parse(command: &str, args: &[String]) -> Result<Options, ()> {
    let mut options = Options {
        pids: Vec::new(),
        modules: Vec::new(),
        json: false,
        cgroup: None,
        watch: false,
        interval: None,
        duration: None,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" if !options.json => options.json = true,
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
fn inspect_modules(paths: &[PathBuf], limits: Limits) -> ModuleInventory {
    let started = Instant::now();
    let mut result = ModuleInventory {
        schema_version: "osslscope.discovery.v1",
        mode: "module",
        modules: Vec::new(),
        errors: Vec::new(),
        totals: WorkTotals::default(),
        limits,
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
            parsed.map(Some)
        })();
        match inspected {
            Ok(Some(info)) => result.modules.push(info),
            Ok(None) => (),
            Err(reason) => result.errors.push(ModuleError {
                input_index,
                reason,
            }),
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
fn render(value: &impl Serialize, json: bool, writer: &mut impl Write) -> io::Result<()> {
    if !json {
        writer.write_all(MEANING.as_bytes())?;
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
                    },
                    interval: options.interval.unwrap_or(Duration::from_secs(1)),
                    duration: options.duration,
                    limits: Limits::default(),
                },
                &mut output,
                &WATCH_INTERRUPTED,
                !options.json,
            )
            .map(|outcome| outcome.exit_code())
        } else if command == "scan" {
            let mut scanner = match super::scope::ScopedScanner::new(
                super::scope::Selection {
                    pids: options.pids,
                    cgroup: options.cgroup,
                    modules: options.modules,
                },
                Limits::default(),
            ) {
                Ok(scanner) => scanner,
                Err(_) => {
                    crate::report::err_line("osslscope discovery: requested scope unavailable");
                    return ExitCode::from(4);
                }
            };
            let result = scanner.snapshot();
            render(&result, options.json, &mut output).map(|()| result.exit_code())
        } else if options.modules.is_empty() {
            let result = snapshot(&SnapshotOptions {
                pids: options.pids,
                limits: Limits::default(),
            });
            render(&result, options.json, &mut output).map(|()| result.exit_code())
        } else {
            let result = inspect_modules(&options.modules, Limits::default());
            render(&result, options.json, &mut output)
                .map(|()| inventory_exit(result.capabilities.inventory))
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
    use super::*;

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
            let result = inspect_modules(&paths, limits);
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
    fn module_read_admission_and_duplicate_cache_use_aggregate_budget() {
        let executable = PathBuf::from("/bin/true");
        let charge = std::fs::metadata(&executable).unwrap().len() + 1;
        let denied = inspect_modules(
            std::slice::from_ref(&executable),
            Limits {
                max_read_bytes: charge - 1,
                ..Limits::default()
            },
        );
        assert_eq!(denied.errors[0].reason, GapReason::ReadLimit);
        assert_eq!(denied.totals.read_bytes, 0);
        let result = inspect_modules(
            &[executable.clone(), executable],
            Limits {
                max_read_bytes: charge,
                ..Limits::default()
            },
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
}
