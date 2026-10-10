//! SPDX-License-Identifier: GPL-3.0-or-later
//! `inspect` — dispatch discovery against a live PID (P1 exit 1).
//!
//! Runs the two-stage harvest and prints the harvest document (P1 schema:
//! `alg_class` + `weak`, never raw provider strings; no runtime
//! addresses — relocation backing travels as file triples plus
//! one-way hashes). Exit 0 on a triggered harvest, 1 on
//! timeout/failure.
use crate::discovery::harvest;
use std::process::ExitCode;
use std::time::Duration;

pub fn run(args: &[String]) -> ExitCode {
    let mut pid: Option<u32> = None;
    let mut provider: Option<std::path::PathBuf> = None;
    let mut object: Option<std::path::PathBuf> = None;
    let mut out: Option<std::path::PathBuf> = None;
    let mut settle = 2u64;
    let mut timeout = 30u64;
    let mut marker: Option<String> = None;
    let mut builtin = false;
    let mut legacy = false;
    let mut table: Option<std::path::PathBuf> = None;
    let mut force_offset: Option<u64> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--help" || a == "-h" {
            println!(
                "usage: osslscope inspect --pid PID --provider SO --object BPF [--out FILE] [--marker M] [--settle S] [--timeout S] [--builtin [--table FILE] [--force-offset N]] [--legacy]"
            );
            println!("  --pid PID: live target to inventory (pinned against pid reuse)");
            println!("  --provider SO: provider .so (or libcrypto with --builtin)");
            println!("  --object BPF: harvest eBPF object (built from crates/ebpf)");
            println!("  --settle S: attach-settle seconds (default 2)");
            println!("  --timeout S: trigger-wait seconds (default 30)");
            println!("  --legacy: also attach ENGINE/low-level tripwires");
            println!("  needs CAP_BPF+CAP_PERFMON (run: osslscope doctor)");
            return ExitCode::SUCCESS;
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
                "--settle" => settle = val(&mut it)?.parse().map_err(|_| "bad --settle")?,
                "--timeout" => timeout = val(&mut it)?.parse().map_err(|_| "bad --timeout")?,
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
        if let Err(e) = r {
            eprintln!("osslscope inspect: {e}");
            return ExitCode::from(2);
        }
    }
    let (Some(pid), Some(provider), Some(object)) = (pid, provider, object) else {
        eprintln!(
            "usage: osslscope inspect --pid PID --provider SO --object BPF [--out FILE] [--marker M] [--settle S] [--timeout S] [--builtin [--table FILE] [--force-offset N]] [--legacy]"
        );
        return ExitCode::from(2);
    };
    let cfg = harvest::Config {
        pid,
        provider,
        object,
        settle: Duration::from_secs(settle),
        timeout: Duration::from_secs(timeout),
        cmdline_marker: marker,
        builtin,
        legacy,
        table,
        force_offset,
    };
    let emit = |doc: &serde_json::Value| {
        let text = serde_json::to_string_pretty(doc).unwrap();
        if let Some(path) = &out {
            std::fs::write(path, &text).map_err(|e| format!("write {}: {e}", path.display()))
        } else {
            println!("{text}");
            Ok(())
        }
    };
    match harvest::run(&cfg) {
        Ok(doc) => {
            if let Err(e) = emit(&doc) {
                eprintln!("osslscope inspect: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Pin recycle: the PARTIAL(pid-recycled) discard doc still
            // travels (never rows), flagged by exit 4.
            if let Some(r) = e.downcast_ref::<harvest::Recycled>() {
                if let Err(e) = emit(&r.doc) {
                    eprintln!("osslscope inspect: {e}");
                    return ExitCode::FAILURE;
                }
                eprintln!("osslscope inspect: {r}");
                return ExitCode::from(4);
            }
            eprintln!("osslscope inspect: {e:#}");
            ExitCode::FAILURE
        }
    }
}
