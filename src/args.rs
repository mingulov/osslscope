//! SPDX-License-Identifier: GPL-3.0-or-later
//! T04 shared CLI argument helpers (R07/R08): one fallible seconds
//! parser with per-flag ranges, checked deadline construction, and
//! default argv redaction. `report` and `check` convert through this
//! module so huge/non-finite inputs are usage errors (exit 2), never
//! panics, and no raw argv reaches artifacts.
use std::time::{Duration, Instant};

/// R08 frozen upper bounds (seconds).
pub const MAX_DURATION_SECS: f64 = 3600.0;
/// Setup/harvest timeout bound.
pub const MAX_TIMEOUT_SECS: f64 = 120.0;
/// Settle bound.
pub const MAX_SETTLE_SECS: f64 = 30.0;
/// Drain-grace bound.
pub const MAX_GRACE_SECS: f64 = 30.0;

/// Placeholder stored wherever a target command line used to be
/// copied (R07: no raw argv in artifacts; pid/comm/exe identity still
/// available through their own fields).
pub const REDACTED_CMDLINE: &str = "(argv-redacted)";

/// Parse a `--duration`/`--timeout`/`--settle`/`--grace` value into a
/// `Duration`. `flag` is the CLI spelling (leading dashes optional).
/// Ranges: duration (0,3600], timeout [0,120], settle [0,30], grace
/// [0,30]. Non-finite, out-of-range, and positive-but-rounding-to-zero
/// inputs are `Err` (the caller exits 2 before any target/BPF side
/// effect). Conversion happens only after validation, so values that
/// used to panic `Duration::from_secs_f64` (e.g. `1e30`) cannot reach it.
pub fn parse_seconds(flag: &str, value: &str) -> Result<Duration, String> {
    let v: f64 = value.parse().map_err(|_| format!("{flag} needs seconds"))?;
    let name = flag.trim_start_matches('-');
    let (allow_zero, max) = match name {
        "duration" => (false, MAX_DURATION_SECS),
        "timeout" => (true, MAX_TIMEOUT_SECS),
        "settle" => (true, MAX_SETTLE_SECS),
        "grace" => (true, MAX_GRACE_SECS),
        _ => return Err(format!("{flag}: unknown time flag")),
    };
    let range_msg = if allow_zero {
        format!("{flag} must be >= 0 seconds and <= {max} seconds")
    } else {
        format!("{flag} must be > 0 seconds and <= {max} seconds")
    };
    if !v.is_finite() {
        return Err(range_msg);
    }
    // Literals that underflow f64 parsing itself (`1e-9999` -> 0.0,
    // `-1e-9999` -> -0.0) carry nonzero significand digits but compare
    // equal to zero: a positive one rounds to zero, a negative one is
    // negative — both invalid. Only the significand counts (the
    // exponent of `0e1` is nonzero, but the value is genuinely zero).
    let significand = value.split(['e', 'E', 'p', 'P']).next().unwrap_or(value);
    if v == 0.0 && significand.bytes().any(|b| matches!(b, b'1'..=b'9')) {
        return Err(range_msg);
    }
    if v < 0.0 || v > max || (!allow_zero && v == 0.0) {
        return Err(range_msg);
    }
    // Bounded and finite: infallible (only NaN/inf/u64-overflow panic).
    let d = Duration::from_secs_f64(v);
    if v > 0.0 && d.is_zero() {
        return Err(format!("{flag} must be > 0 seconds (value rounds to zero)"));
    }
    Ok(d)
}

/// Checked duration addition for deadline construction: overflow is an
/// error, never a wrap or panic.
pub fn checked_add(a: Duration, b: Duration) -> Result<Duration, String> {
    a.checked_add(b)
        .ok_or_else(|| "deadline arithmetic overflow".to_string())
}

/// Checked `Instant + Duration`: `None` on overflow.
pub fn deadline_at(start: Instant, after: Duration) -> Option<Instant> {
    start.checked_add(after)
}

/// Parse a `--force-offset` value: decimal or `0x`/`0X` hex.
/// Shared by inspect/report/check/doctor so the forensics hatch
/// spells the same everywhere (R09 explicit override).
pub fn parse_force_offset(value: &str) -> Result<u64, String> {
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|_| format!("--force-offset needs a decimal or 0x-hex integer (got {value:?})"))
}

/// Redact a spawn argv: the target strings are never copied into
/// evidence, logs, or debug output.
pub fn redact_spawn_argv(_argv: &[String]) -> String {
    REDACTED_CMDLINE.to_string()
}

/// Redact raw `/proc/<pid>/cmdline` bytes: same placeholder, no input
/// bytes retained (see `redact_spawn_argv`).
pub fn redact_proc_cmdline(_raw: &[u8]) -> String {
    REDACTED_CMDLINE.to_string()
}
