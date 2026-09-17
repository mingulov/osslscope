//! `inspect` — dispatch discovery against a live PID (P1 exit 1).
//!
//! Runs the two-stage harvest and prints the harvest document (P1 schema:
//! `alg_class` + `weak`, never raw provider strings; `addr` present for
//! P0-schema compat, redacted before golden comparison). Exit 0 on a
//! triggered harvest, 1 on timeout/failure.
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
                    let n = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
                    let v = match n {
                        Some(h) => u64::from_str_radix(h, 16),
                        None => s.parse::<u64>(),
                    };
                    force_offset = Some(v.map_err(|_| "bad --force-offset")?);
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
            "usage: osslscope inspect --pid PID --provider SO --object BPF [--out FILE] [--marker M] [--builtin [--table FILE] [--force-offset N]] [--legacy]"
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
    match harvest::run(&cfg) {
        Ok(doc) => {
            let text = serde_json::to_string_pretty(&doc).unwrap();
            if let Some(path) = out {
                if let Err(e) = std::fs::write(&path, &text) {
                    eprintln!("osslscope inspect: write {}: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            } else {
                println!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("osslscope inspect: {e:#}");
            ExitCode::FAILURE
        }
    }
}
