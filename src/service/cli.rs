//! SPDX-License-Identifier: GPL-3.0-or-later
//! §1 service CLI and config: flags, defaults, ranges, TOML admission.
//!
//! `osslscope service [flags]`. `--flag=value` is rejected everywhere
//! (exit 2). All time flags parse through `args::parse_seconds`.
//! Precedence: explicit CLI > config file > built-in default. Scalars
//! override; `pid`/`module` concatenate; scalar `cgroup` overrides.

use std::path::PathBuf;
use std::time::Duration;

/// §1.2 frozen defaults.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30);
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_GRACE: Duration = Duration::from_secs(5);
pub const DEFAULT_QUEUE_BYTES: u64 = 1_048_576;
pub const DEFAULT_QUEUE_EVENTS: u64 = 1_024;
pub const DEFAULT_ROTATE_BYTES: u64 = 67_108_864;
pub const DEFAULT_ROTATE_INTERVAL: Duration = Duration::from_secs(3600);
pub const DEFAULT_RETAIN_WINDOWS: u64 = 2_880;
pub const DEFAULT_RETAIN_BYTES: u64 = 1_073_741_824;

/// §1.2 frozen ranges (inclusive).
pub const MIN_QUEUE_BYTES: u64 = 65_536;
pub const MAX_QUEUE_BYTES: u64 = 268_435_456;
pub const MIN_QUEUE_EVENTS: u64 = 64;
pub const MAX_QUEUE_EVENTS: u64 = 4_096;
pub const MIN_ROTATE_BYTES: u64 = 1_048_576;
pub const MAX_ROTATE_BYTES: u64 = 1_073_741_824;
pub const MIN_RETAIN_WINDOWS: u64 = 1;
pub const MAX_RETAIN_WINDOWS: u64 = u32::MAX as u64;
pub const MIN_RETAIN_BYTES: u64 = 67_108_864;

/// §1.3 config admission bound (mirrors `policy_config::MAX_BYTES`).
pub const CONFIG_MAX_BYTES: usize = 65_536;

/// `--format`: stderr diagnostics only (§1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// One JSON object per diagnostic line (default).
    #[default]
    Json,
    /// `osslscope: <msg>` lines + one per-window summary line.
    Human,
}

/// Fully resolved service configuration (§1.2 + §1.3 precedence).
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub window: Duration,
    pub interval: Duration,
    pub timeout: Duration,
    pub grace: Duration,
    pub format: Format,
    pub queue_bytes: u64,
    pub queue_events: u64,
    pub rotate_bytes: u64,
    pub rotate_interval: Duration,
    pub retain_windows: u64,
    pub retain_bytes: u64,
    pub policy: Option<PathBuf>,
    pub out: PathBuf,
    pub stream: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub reset_sequence: bool,
    pub pids: Vec<u32>,
    pub modules: Vec<PathBuf>,
    pub cgroup: Option<PathBuf>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            interval: DEFAULT_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
            grace: DEFAULT_GRACE,
            format: Format::Json,
            queue_bytes: DEFAULT_QUEUE_BYTES,
            queue_events: DEFAULT_QUEUE_EVENTS,
            rotate_bytes: DEFAULT_ROTATE_BYTES,
            rotate_interval: DEFAULT_ROTATE_INTERVAL,
            retain_windows: DEFAULT_RETAIN_WINDOWS,
            retain_bytes: DEFAULT_RETAIN_BYTES,
            policy: None,
            out: PathBuf::new(),
            stream: None,
            config_path: None,
            reset_sequence: false,
            pids: Vec::new(),
            modules: Vec::new(),
            cgroup: None,
        }
    }
}

/// Usage text for `service --help` (exit 0).
pub const USAGE: &str = "usage: osslscope service --out DIR [--pid PID ...] [--module PATH ...] [--cgroup PATH]\n       [--window S] [--interval S] [--timeout S] [--grace S] [--format json|human]\n       [--queue-bytes N] [--queue-events N] [--rotate-bytes N] [--rotate-interval S]\n       [--retain-windows N] [--retain-bytes N] [--policy FILE] [--stream PATH]\n       [--config FILE] [--reset-sequence]\n";

/// Parse `service` argv (after the subcommand word) into a resolved
/// config. Pure: no filesystem side effects beyond READING `--config`
/// (admission only). Every refusal is `Err` (caller exits 2).
pub fn parse(args: &[String]) -> Result<ServiceConfig, String> {
    let mut cfg = ServiceConfig::default();
    // CLI presence per scalar (precedence over the file).
    let mut cli_cgroup = false;
    let mut cli_window = false;
    let mut cli_interval = false;
    let mut cli_timeout = false;
    let mut cli_grace = false;
    let mut cli_format = false;
    let mut cli_queue_bytes = false;
    let mut cli_queue_events = false;
    let mut cli_rotate_bytes = false;
    let mut cli_rotate_interval = false;
    let mut cli_retain_windows = false;
    let mut cli_retain_bytes = false;
    let mut cli_policy = false;
    let mut cli_out = false;
    let mut cli_stream = false;
    let mut out_set = false;
    let mut cgroup_seen = false;
    let mut config_cli: Option<PathBuf> = None;

    let mut it = args.iter().peekable();
    while let Some(arg) = it.next() {
        if arg == "--help" || arg == "-h" {
            return Err("__help__".to_string());
        }
        if arg == "--reset-sequence" {
            cfg.reset_sequence = true;
            continue;
        }
        if arg == "--config" {
            let v = next_value(arg, &mut it)?;
            reject_flag_value(arg, &v)?;
            config_cli = Some(PathBuf::from(v));
            continue;
        }
        let (flag, inline) = match arg.split_once('=') {
            Some((f, _)) if f.starts_with("--") => (f, true),
            _ => (arg.as_str(), false),
        };
        // `--flag=value` is rejected everywhere (existing rule).
        if inline {
            return Err(format!("{flag} does not take =value (use: {flag} value)"));
        }
        match flag {
            "--pid" => {
                let v = next_value(flag, &mut it)?;
                cfg.pids.push(parse_pid(&v)?);
            }
            "--module" => {
                let v = next_value(flag, &mut it)?;
                reject_flag_value(flag, &v)?;
                cfg.modules.push(PathBuf::from(v));
            }
            "--cgroup" => {
                if cgroup_seen {
                    return Err("service takes at most one --cgroup".to_string());
                }
                cgroup_seen = true;
                cli_cgroup = true;
                let v = next_value(flag, &mut it)?;
                reject_flag_value(flag, &v)?;
                cfg.cgroup = Some(PathBuf::from(v));
            }
            "--policy" => {
                cli_policy = true;
                let v = next_value(flag, &mut it)?;
                reject_flag_value(flag, &v)?;
                cfg.policy = Some(PathBuf::from(v));
            }
            "--out" => {
                cli_out = true;
                out_set = true;
                let v = next_value(flag, &mut it)?;
                reject_flag_value(flag, &v)?;
                cfg.out = PathBuf::from(v);
            }
            "--stream" => {
                cli_stream = true;
                let v = next_value(flag, &mut it)?;
                reject_flag_value(flag, &v)?;
                cfg.stream = Some(PathBuf::from(v));
            }
            "--window" => {
                cli_window = true;
                let v = next_value(flag, &mut it)?;
                cfg.window = crate::args::parse_seconds("window", &v)?;
            }
            "--interval" => {
                cli_interval = true;
                let v = next_value(flag, &mut it)?;
                cfg.interval = crate::args::parse_seconds("interval", &v)?;
            }
            "--timeout" => {
                cli_timeout = true;
                let v = next_value(flag, &mut it)?;
                cfg.timeout = crate::args::parse_seconds("timeout", &v)?;
            }
            "--grace" => {
                cli_grace = true;
                let v = next_value(flag, &mut it)?;
                cfg.grace = crate::args::parse_seconds("grace", &v)?;
            }
            "--format" => {
                cli_format = true;
                let v = next_value(flag, &mut it)?;
                cfg.format = match v.as_str() {
                    "json" => Format::Json,
                    "human" => Format::Human,
                    _ => return Err("service --format must be json|human".to_string()),
                };
            }
            "--queue-bytes" => {
                cli_queue_bytes = true;
                let v = next_value(flag, &mut it)?;
                cfg.queue_bytes = parse_count(flag, &v, MIN_QUEUE_BYTES, MAX_QUEUE_BYTES)?;
            }
            "--queue-events" => {
                cli_queue_events = true;
                let v = next_value(flag, &mut it)?;
                cfg.queue_events = parse_count(flag, &v, MIN_QUEUE_EVENTS, MAX_QUEUE_EVENTS)?;
            }
            "--rotate-bytes" => {
                cli_rotate_bytes = true;
                let v = next_value(flag, &mut it)?;
                cfg.rotate_bytes = parse_count(flag, &v, MIN_ROTATE_BYTES, MAX_ROTATE_BYTES)?;
            }
            "--rotate-interval" => {
                cli_rotate_interval = true;
                let v = next_value(flag, &mut it)?;
                cfg.rotate_interval = crate::args::parse_seconds("rotate-interval", &v)?;
            }
            "--retain-windows" => {
                cli_retain_windows = true;
                let v = next_value(flag, &mut it)?;
                cfg.retain_windows = parse_count(flag, &v, MIN_RETAIN_WINDOWS, MAX_RETAIN_WINDOWS)?;
            }
            "--retain-bytes" => {
                cli_retain_bytes = true;
                let v = next_value(flag, &mut it)?;
                cfg.retain_bytes = parse_count(flag, &v, MIN_RETAIN_BYTES, u64::MAX)?;
            }
            other => return Err(format!("service: unknown flag '{other}'")),
        }
    }
    cfg.config_path = config_cli.clone();
    // Config file (admission only): CLI > file > default.
    if let Some(path) = config_cli {
        let file = read_config(&path)?;
        if file.cgroup.is_some() && !cli_cgroup {
            cfg.cgroup = file.cgroup;
        }
        if !cli_window && file.window.is_some() {
            cfg.window = file.window.unwrap();
        }
        if !cli_interval && file.interval.is_some() {
            cfg.interval = file.interval.unwrap();
        }
        if !cli_timeout && file.timeout.is_some() {
            cfg.timeout = file.timeout.unwrap();
        }
        if !cli_grace && file.grace.is_some() {
            cfg.grace = file.grace.unwrap();
        }
        if !cli_format && file.format.is_some() {
            cfg.format = file.format.unwrap();
        }
        if !cli_queue_bytes && file.queue_bytes.is_some() {
            cfg.queue_bytes = file.queue_bytes.unwrap();
        }
        if !cli_queue_events && file.queue_events.is_some() {
            cfg.queue_events = file.queue_events.unwrap();
        }
        if !cli_rotate_bytes && file.rotate_bytes.is_some() {
            cfg.rotate_bytes = file.rotate_bytes.unwrap();
        }
        if !cli_rotate_interval && file.rotate_interval.is_some() {
            cfg.rotate_interval = file.rotate_interval.unwrap();
        }
        if !cli_retain_windows && file.retain_windows.is_some() {
            cfg.retain_windows = file.retain_windows.unwrap();
        }
        if !cli_retain_bytes && file.retain_bytes.is_some() {
            cfg.retain_bytes = file.retain_bytes.unwrap();
        }
        if !cli_policy && file.policy.is_some() {
            cfg.policy = file.policy;
        }
        if !cli_out && file.out.is_some() {
            cfg.out = file.out.unwrap();
            out_set = true;
        }
        if !cli_stream && file.stream.is_some() {
            cfg.stream = file.stream;
        }
        // `pid`/`module` concatenate across CLI and file.
        let mut pids = file.pids;
        pids.append(&mut cfg.pids);
        cfg.pids = pids;
        let mut modules = file.modules;
        modules.append(&mut cfg.modules);
        cfg.modules = modules;
    }
    // The `report.rs:192-193` positivity check (parser arms allow 0).
    if cfg.timeout.is_zero() || cfg.grace.is_zero() {
        return Err("--timeout and --grace must be positive".into());
    }
    if !out_set {
        return Err("service requires --out DIR".to_string());
    }
    // New 6B freeze: windows need a bounded observed set.
    if cfg.pids.is_empty() && cfg.cgroup.is_none() {
        return Err("service requires at least one of --pid/--cgroup".to_string());
    }
    Ok(cfg)
}

fn next_value<'a>(
    flag: &str,
    it: &mut std::iter::Peekable<std::slice::Iter<'a, String>>,
) -> Result<String, String> {
    match it.next() {
        Some(v) if !v.starts_with("--") || !v.is_empty() && v.parse::<f64>().is_ok() => {
            Ok(v.to_string())
        }
        Some(v) if v.is_empty() => Ok(v.to_string()),
        _ => Err(format!("{flag} needs a value")),
    }
}

/// A flag value that looks like another flag is a missing value
/// (except numeric spellings, which `parse_seconds`/counts judge).
fn reject_flag_value(flag: &str, value: &str) -> Result<(), String> {
    if value.starts_with("--") && value.parse::<f64>().is_err() {
        return Err(format!("{flag} needs a value"));
    }
    if value.is_empty() {
        return Err(format!("{flag} needs a value"));
    }
    Ok(())
}

/// `--pid` validates identically to `inventory/cli.rs:85`:
/// all-ASCII-digits, `1..=i32::MAX`.
fn parse_pid(value: &str) -> Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("--pid needs a process id".to_string());
    }
    let pid: u32 = value
        .parse()
        .map_err(|_| "--pid needs a process id".to_string())?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("--pid needs a process id".to_string());
    }
    Ok(pid)
}

/// `N` counts: non-numeric/overflowing values are exit 2, then the
/// frozen range check (same pre-side-effect rule as `parse_seconds`).
fn parse_count(flag: &str, value: &str, min: u64, max: u64) -> Result<u64, String> {
    let n: u64 = value
        .parse()
        .map_err(|_| format!("{flag} needs an integer {min}..={max}"))?;
    if n < min || n > max {
        return Err(format!("{flag} needs an integer {min}..={max}"));
    }
    Ok(n)
}

/// §1.3 TOML time value: the same float-seconds spelling as CLI,
/// written as a TOML string, float, or integer (all validated
/// through `parse_seconds` against the §1.2 ranges).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
enum TimeValue {
    Text(String),
    Float(f64),
    Int(i64),
}

impl TimeValue {
    fn spell(&self) -> String {
        match self {
            TimeValue::Text(s) => s.clone(),
            TimeValue::Float(f) => format!("{f:?}"),
            TimeValue::Int(i) => i.to_string(),
        }
    }
}

/// §1.3 TOML file shape (kebab-case scalars, `deny_unknown_fields`).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    version: Option<i64>,
    window: Option<TimeValue>,
    interval: Option<TimeValue>,
    timeout: Option<TimeValue>,
    grace: Option<TimeValue>,
    format: Option<String>,
    #[serde(rename = "queue-bytes")]
    queue_bytes: Option<u64>,
    #[serde(rename = "queue-events")]
    queue_events: Option<u64>,
    #[serde(rename = "rotate-bytes")]
    rotate_bytes: Option<u64>,
    #[serde(rename = "rotate-interval")]
    rotate_interval: Option<TimeValue>,
    #[serde(rename = "retain-windows")]
    retain_windows: Option<u64>,
    #[serde(rename = "retain-bytes")]
    retain_bytes: Option<u64>,
    policy: Option<String>,
    out: Option<String>,
    stream: Option<String>,
    #[serde(default)]
    pid: Vec<i64>,
    #[serde(default)]
    module: Vec<String>,
    cgroup: Option<String>,
}

/// Validated file values (ranges checked, times parsed).
#[derive(Debug, Default)]
struct ValidFile {
    window: Option<Duration>,
    interval: Option<Duration>,
    timeout: Option<Duration>,
    grace: Option<Duration>,
    format: Option<Format>,
    queue_bytes: Option<u64>,
    queue_events: Option<u64>,
    rotate_bytes: Option<u64>,
    rotate_interval: Option<Duration>,
    retain_windows: Option<u64>,
    retain_bytes: Option<u64>,
    policy: Option<PathBuf>,
    out: Option<PathBuf>,
    stream: Option<PathBuf>,
    pids: Vec<u32>,
    modules: Vec<PathBuf>,
    cgroup: Option<PathBuf>,
}

/// Read + admit `--config` (same open discipline as
/// `policy_config::load`: `O_NONBLOCK | O_CLOEXEC`, regular file
/// only, ≤64 KiB + 1 probe byte, UTF-8, `deny_unknown_fields`).
fn read_config(path: &std::path::Path) -> Result<ValidFile, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "cannot open service config file".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect service config file".to_string())?;
    if !metadata.is_file() {
        return Err("service config must be a regular file".to_string());
    }
    let mut bytes = Vec::with_capacity(CONFIG_MAX_BYTES + 1);
    file.take((CONFIG_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read service config file".to_string())?;
    if bytes.len() > CONFIG_MAX_BYTES {
        return Err("service config exceeds 65536 bytes".to_string());
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "service config must be UTF-8".to_string())?;
    // Never format a TOML error (may carry source excerpts).
    let raw: FileConfig =
        toml::from_str(text).map_err(|_| "invalid service config TOML".to_string())?;
    if raw.version != Some(1) {
        return Err("service config version must be integer 1".to_string());
    }
    let mut out = ValidFile::default();
    if let Some(v) = raw.window {
        out.window = Some(crate::args::parse_seconds("window", &v.spell())?);
    }
    if let Some(v) = raw.interval {
        out.interval = Some(crate::args::parse_seconds("interval", &v.spell())?);
    }
    if let Some(v) = raw.timeout {
        out.timeout = Some(crate::args::parse_seconds("timeout", &v.spell())?);
    }
    if let Some(v) = raw.grace {
        out.grace = Some(crate::args::parse_seconds("grace", &v.spell())?);
    }
    if let Some(v) = raw.format {
        out.format = Some(match v.as_str() {
            "json" => Format::Json,
            "human" => Format::Human,
            _ => return Err("service config format must be json|human".to_string()),
        });
    }
    if let Some(n) = raw.queue_bytes {
        out.queue_bytes = Some(check_count(
            "--queue-bytes",
            n,
            MIN_QUEUE_BYTES,
            MAX_QUEUE_BYTES,
        )?);
    }
    if let Some(n) = raw.queue_events {
        out.queue_events = Some(check_count(
            "--queue-events",
            n,
            MIN_QUEUE_EVENTS,
            MAX_QUEUE_EVENTS,
        )?);
    }
    if let Some(n) = raw.rotate_bytes {
        out.rotate_bytes = Some(check_count(
            "--rotate-bytes",
            n,
            MIN_ROTATE_BYTES,
            MAX_ROTATE_BYTES,
        )?);
    }
    if let Some(v) = raw.rotate_interval {
        out.rotate_interval = Some(crate::args::parse_seconds("rotate-interval", &v.spell())?);
    }
    if let Some(n) = raw.retain_windows {
        out.retain_windows = Some(check_count(
            "--retain-windows",
            n,
            MIN_RETAIN_WINDOWS,
            MAX_RETAIN_WINDOWS,
        )?);
    }
    if let Some(n) = raw.retain_bytes {
        out.retain_bytes = Some(check_count(
            "--retain-bytes",
            n,
            MIN_RETAIN_BYTES,
            u64::MAX,
        )?);
    }
    if let Some(v) = raw.policy {
        out.policy = Some(PathBuf::from(v));
    }
    if let Some(v) = raw.out {
        out.out = Some(PathBuf::from(v));
    }
    if let Some(v) = raw.stream {
        out.stream = Some(PathBuf::from(v));
    }
    for pid in raw.pid {
        if pid < 1 || pid > i64::from(i32::MAX) {
            return Err("service config pid elements must be 1..=i32::MAX".to_string());
        }
        out.pids.push(pid as u32);
    }
    for m in raw.module {
        out.modules.push(PathBuf::from(m));
    }
    if let Some(c) = raw.cgroup {
        out.cgroup = Some(PathBuf::from(c));
    }
    Ok(out)
}

fn check_count(flag: &str, n: u64, min: u64, max: u64) -> Result<u64, String> {
    if n < min || n > max {
        return Err(format!("service config {flag} out of range {min}..={max}"));
    }
    Ok(n)
}
