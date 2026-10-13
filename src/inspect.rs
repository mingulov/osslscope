//! SPDX-License-Identifier: GPL-3.0-or-later
//! `inspect` — dispatch discovery against a live PID (P1 exit 1).
//!
//! Runs the two-stage harvest and prints the harvest document (P1 schema:
//! `alg_class` + `weak`, never raw provider strings; no runtime
//! addresses — relocation backing travels as file triples plus
//! one-way hashes).
//!
//! Admission shares [`crate::args::parse_seconds`] with report/check
//! (R07/F08): float seconds, `--timeout` [0,120] default 60,
//! `--settle` [0,30] default 2. Exits: 0 normal, 2 usage, 3 PARTIAL
//! harvest, 4 environment/recycle (retained even when the recycle
//! discard delivery fails), 1 artifact delivery failure.
use crate::discovery::harvest;
use std::process::ExitCode;
use std::time::Duration;

/// Default trigger-wait (shared with report/check harvest timeout).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Default attach-settle (shared with report/check).
pub const DEFAULT_SETTLE: Duration = Duration::from_secs(2);

/// Parsed `inspect` arguments (R07 seam: parsing and outcome
/// classification are unit/integration-testable without BPF).
#[derive(Debug)]
pub struct InspectArgs {
    pub pid: u32,
    pub provider: std::path::PathBuf,
    pub object: std::path::PathBuf,
    pub out: Option<std::path::PathBuf>,
    pub settle: Duration,
    pub timeout: Duration,
    pub marker: Option<String>,
    pub builtin: bool,
    pub legacy: bool,
    pub table: Option<std::path::PathBuf>,
    pub force_offset: Option<u64>,
}

impl InspectArgs {
    fn harvest_config(&self) -> harvest::Config {
        harvest::Config {
            pid: self.pid,
            provider: self.provider.clone(),
            object: self.object.clone(),
            settle: self.settle,
            timeout: self.timeout,
            cmdline_marker: self.marker.clone(),
            builtin: self.builtin,
            legacy: self.legacy,
            table: self.table.clone(),
            force_offset: self.force_offset,
            // inspect attaches to a live pid: mid-life observation, never
            // from birth (F-B/A14 — quiet attaches stay PARTIAL).
            observed_from_birth: false,
        }
    }
}

const USAGE: &str = "usage: osslscope inspect --pid PID --provider SO --object BPF [--out FILE] [--marker M] [--settle S] [--timeout S] [--builtin [--table FILE] [--force-offset N]] [--legacy]";

fn print_help() {
    println!("{USAGE}");
    println!("  --pid PID: live target to inventory (pinned against pid reuse)");
    println!("  --provider SO: provider .so (or libcrypto with --builtin)");
    println!("  --object BPF: harvest eBPF object (built from crates/ebpf)");
    println!("  --settle S: attach-settle seconds (default 2)");
    println!("  --timeout S: trigger-wait seconds (default 60)");
    println!("  --legacy: also attach ENGINE/low-level tripwires");
    println!("  needs CAP_BPF+CAP_PERFMON (run: osslscope doctor)");
}

/// Parse `inspect` argv (R07 seam). Time flags route through the one
/// shared bounded parser; every error is a usage error (the caller
/// exits 2 before any provider/BPF side effect).
pub fn parse(args: &[String]) -> Result<InspectArgs, String> {
    let mut pid: Option<u32> = None;
    let mut provider: Option<std::path::PathBuf> = None;
    let mut object: Option<std::path::PathBuf> = None;
    let mut out: Option<std::path::PathBuf> = None;
    let mut settle_raw: Option<String> = None;
    let mut timeout_raw: Option<String> = None;
    let mut marker: Option<String> = None;
    let mut builtin = false;
    let mut legacy = false;
    let mut table: Option<std::path::PathBuf> = None;
    let mut force_offset: Option<u64> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--help" || a == "-h" {
            // Handled in run() (help short-circuits there); reaching
            // the seam directly is a usage error, never silent.
            return Err("inspect --help is handled by the entrypoint".to_string());
        }
        let val = |it: &mut std::slice::Iter<String>| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("missing value for {a}"))
        };
        let r: Result<(), String> = (|| {
            match a.as_str() {
                "--pid" => pid = Some(val(&mut it)?.parse().map_err(|_| "bad --pid")?),
                "--provider" => provider = Some(val(&mut it)?.into()),
                "--object" => object = Some(val(&mut it)?.into()),
                "--out" => out = Some(val(&mut it)?.into()),
                "--settle" => settle_raw = Some(val(&mut it)?),
                "--timeout" => timeout_raw = Some(val(&mut it)?),
                "--marker" => marker = Some(val(&mut it)?),
                "--builtin" => builtin = true,
                "--legacy" => legacy = true,
                "--table" => table = Some(val(&mut it)?.into()),
                "--force-offset" => {
                    let s = val(&mut it)?;
                    force_offset = Some(crate::args::parse_force_offset(&s)?);
                }
                _ => return Err(format!("unknown arg {a}")),
            }
            Ok(())
        })();
        r?;
    }
    let (Some(pid), Some(provider), Some(object)) = (pid, provider, object) else {
        return Err(USAGE.to_string());
    };
    // Single conversion point shared with report/check (R08 bounds;
    // rejects 1e30/NaN/inf/negatives/zero-rounding before any
    // provider/BPF side effect). Defaults are exact.
    let settle = match &settle_raw {
        Some(s) => crate::args::parse_seconds("--settle", s)?,
        None => DEFAULT_SETTLE,
    };
    let timeout = match &timeout_raw {
        Some(s) => crate::args::parse_seconds("--timeout", s)?,
        None => DEFAULT_TIMEOUT,
    };
    Ok(InspectArgs {
        pid,
        provider,
        object,
        out,
        settle,
        timeout,
        marker,
        builtin,
        legacy,
        table,
        force_offset,
    })
}

/// True when a harvested document is PARTIAL (COMPLETE provider docs
/// carry no `status` key — P1 byte-compat — so only an explicit
/// PARTIAL status counts).
pub fn is_partial_doc(doc: &serde_json::Value) -> bool {
    doc.get("status").and_then(|s| s.as_str()) == Some("PARTIAL")
}

/// Production artifact emitter (R07 seam): serialize the harvest
/// document (pretty JSON, trailing newline) and deliver it to
/// `--out` or stdout. `run()` passes a live stdout; tests pass real
/// writers (byte buffer, file path, closed socketpair) to prove
/// delivery classification end to end.
pub fn emit_doc(
    doc: &serde_json::Value,
    out: Option<&std::path::Path>,
    stdout: &mut dyn std::io::Write,
) -> Result<(), String> {
    // H7-T6: `Value` serialization is infallible; the fallback
    // exists only to shed the panic shape (never observed).
    let text = serde_json::to_string_pretty(doc).unwrap_or_else(|_| "{}".to_string());
    if let Some(path) = out {
        std::fs::write(path, &text).map_err(|e| format!("write {}: {e}", path.display()))
    } else {
        // Fallible stdout write + flush (never println!: a broken
        // pipe is a delivery error, exit 1, not a panic/101).
        // Byte-identical to the old println! (text + newline).
        let mut bytes = text.into_bytes();
        bytes.push(b'\n');
        stdout
            .write_all(&bytes)
            .and_then(|()| stdout.flush())
            .map_err(|e| format!("write stdout: {e}"))
    }
}

/// Run one harvest with injected effects (R07 seam): `harvest`
/// replaces [`harvest::run`], `emit` replaces the stdout/file write.
/// Exit table: 0 normal, 3 PARTIAL, 4 environment/recycle, 1
/// artifact delivery failure — except a failed recycle-discard
/// delivery retains 4 (no-verdict precedes artifact failure).
/// (Usage/2 never reaches this function.)
pub fn run_with(
    cfg: &harvest::Config,
    harvest: impl FnOnce(&harvest::Config) -> anyhow::Result<serde_json::Value>,
    emit: impl FnOnce(&serde_json::Value) -> Result<(), String>,
) -> ExitCode {
    match harvest(cfg) {
        Ok(doc) => {
            let partial = is_partial_doc(&doc);
            if let Err(e) = emit(&doc) {
                crate::report::err_line(&format!("osslscope inspect: {e}"));
                return ExitCode::FAILURE;
            }
            if partial {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            // Pin recycle: the PARTIAL(pid-recycled) discard doc is
            // still attempted (never rows), flagged by exit 4.
            // Recycle/no-verdict 4 precedes artifact failure 1 (plan
            // exit precedence), so a failed discard delivery is
            // reported but retains exit 4.
            if let Some(r) = e.downcast_ref::<harvest::Recycled>() {
                if let Err(e) = emit(&r.doc) {
                    crate::report::err_line(&format!("osslscope inspect: {e}"));
                }
                crate::report::err_line(&format!("osslscope inspect: {r}"));
                return ExitCode::from(4);
            }
            crate::report::err_line(&format!("osslscope inspect: {e:#}"));
            ExitCode::from(4)
        }
    }
}

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }
    let parsed = match parse(args) {
        Ok(p) => p,
        Err(e) => {
            crate::report::err_line(&format!("osslscope inspect: {e}"));
            return ExitCode::from(2);
        }
    };
    let cfg = parsed.harvest_config();
    let out = parsed.out.clone();
    let emit = |doc: &serde_json::Value| {
        let stdout = std::io::stdout();
        let mut locked = stdout.lock();
        emit_doc(doc, out.as_deref(), &mut locked)
    };
    run_with(&cfg, harvest::run, emit)
}
