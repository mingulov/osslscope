//! SPDX-License-Identifier: GPL-3.0-or-later
//! `service-witness`: harness-side signal observer invocation + verdict.
//!
//! Two modes (both harness-use; the 24h qual drives them):
//!
//! - Observe: `service-witness --log PATH (--cgroup DIR | --pid N
//!   [--pid N...]) [--signal-test PID,SIGNO]` — seizes the workload
//!   and appends `signal-witness.jsonl`. Diverges (the harness kills
//!   the observer at teardown; killing the tracer auto-detaches).
//! - Adjudicate: `service-witness --adjudicate --log PATH --timeline
//!   PATH` — runs the §9/L5 oracle over the witness log + the
//!   harness-timeline JSON and prints the verdict JSON.
//!
//! Exits: observe diverges (usage errors exit 2 pre-start, mirroring
//! service admission); adjudicate exits 0 pass / 1 fail / 4 void
//! (nothing to judge — rerun required) / 2 usage or unreadable
//! input. The harness reads the verdict JSON, not just the code.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::service::witness::{
    AttemptRecord, AttemptTracerConfig, ExternalEvent, HarnessSend, ObserverConfig, OracleInput,
    SignalVerdict, WitnessEntry, adjudicate, run_attempt_tracer, run_observer,
};

const HELP: &str = "usage: osslscope service-witness --log PATH (--cgroup DIR | --pid N [--pid N...]) [--signal-test PID,SIGNO]\n       osslscope service-witness --adjudicate --log PATH --timeline PATH\n\nharness-side signal observer (6B §9/L5). Observe mode seizes the workload\ncgroup/pids via PTRACE_SEIZE and appends signal-witness.jsonl entries;\nadjudicate mode judges the log against the harness timeline.\n\ntimeline JSON: { harness_pid, observer_pid, service_pids[], workload[],\n  canary[], quiet_window:[start_ns,end_ns], sends[], external_events[] }\nverdict JSON: { verdict: pass|fail|void, detail, annotated }\nadjudicate exits: 0 pass, 1 fail, 4 void (rerun), 2 usage/unreadable input.\nadjudicate also takes [--attempt-log PATH] (F8c independent attempt\nevidence; absent = no attempt evidence — uncorroborated self-reports\nthen VOID).";

const TRACE_HELP: &str = "usage: osslscope service-attempt-trace --log PATH [--suspect-pid-file PATH] -- CMD [ARGS...]\n\nharness-side signal-attempt tracer (6B L5/F8c). Supervises a suspect\ncommand under a seccomp RET_TRACE filter on the kill family and\nappends attempt-witness.jsonl entries, one per traced send.\nExits 0 (supervised to completion), 2 (usage/spawn failure),\n3 (supervision hole — attempt evidence void).";

fn refuse(msg: &str) -> ExitCode {
    crate::report::err_line(&format!("osslscope service-witness: {msg}"));
    ExitCode::from(2)
}

/// Parsed observe-mode arguments (pure — unit-tested without ptrace).
#[derive(Debug, PartialEq, Eq)]
struct ObserveArgs {
    log: PathBuf,
    cgroup_procs: Option<PathBuf>,
    pids: Vec<i32>,
    signal_test: Option<(i32, i32)>,
}

fn parse_pids(values: &[String]) -> Result<Vec<i32>, String> {
    values
        .iter()
        .map(|v| {
            v.parse::<i32>()
                .map_err(|_| format!("--pid expects an integer pid, got {v:?}"))
                .and_then(|p| {
                    if p > 0 {
                        Ok(p)
                    } else {
                        Err(format!("--pid expects a positive pid, got {v:?}"))
                    }
                })
        })
        .collect()
}

fn parse_observe(argv: &[String]) -> Result<ObserveArgs, String> {
    let mut log: Option<PathBuf> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut pids: Vec<String> = Vec::new();
    let mut signal_test: Option<(i32, i32)> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--log" => {
                i += 1;
                let v = argv.get(i).ok_or("--log needs a path")?;
                if log.is_some() {
                    return Err("service-witness takes at most one --log".to_string());
                }
                log = Some(PathBuf::from(v));
            }
            "--cgroup" => {
                i += 1;
                let v = argv.get(i).ok_or("--cgroup needs a path")?;
                if cgroup.is_some() {
                    return Err("service-witness takes at most one --cgroup".to_string());
                }
                cgroup = Some(PathBuf::from(v).join("cgroup.procs"));
            }
            "--pid" => {
                i += 1;
                let v = argv.get(i).ok_or("--pid needs a pid")?;
                pids.push(v.clone());
            }
            "--signal-test" => {
                i += 1;
                let v = argv.get(i).ok_or("--signal-test needs PID,SIGNO")?;
                if signal_test.is_some() {
                    return Err("service-witness takes at most one --signal-test".to_string());
                }
                let (pid, signo) = v.split_once(',').ok_or("--signal-test needs PID,SIGNO")?;
                signal_test = Some((
                    pid.parse::<i32>()
                        .map_err(|_| format!("--signal-test needs PID,SIGNO, got {v:?}"))?,
                    signo
                        .parse::<i32>()
                        .map_err(|_| format!("--signal-test needs PID,SIGNO, got {v:?}"))?,
                ));
            }
            other => return Err(format!("service-witness: unknown flag {other:?}")),
        }
        i += 1;
    }
    let log = log.ok_or("--log is required")?;
    if cgroup.is_none() && pids.is_empty() {
        return Err("--cgroup or at least one --pid is required".to_string());
    }
    Ok(ObserveArgs {
        log,
        cgroup_procs: cgroup,
        pids: parse_pids(&pids)?,
        signal_test,
    })
}

/// Parsed `service-attempt-trace` arguments (pure — unit-tested).
#[derive(Debug, PartialEq, Eq)]
struct AttemptTraceArgs {
    log: PathBuf,
    suspect_pid_file: Option<PathBuf>,
    argv: Vec<String>,
}

fn parse_attempt_trace(argv: &[String]) -> Result<AttemptTraceArgs, String> {
    let mut log: Option<PathBuf> = None;
    let mut suspect_pid_file: Option<PathBuf> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--log" => {
                i += 1;
                let v = argv.get(i).ok_or("--log needs a path")?;
                if log.is_some() {
                    return Err("service-attempt-trace takes at most one --log".to_string());
                }
                log = Some(PathBuf::from(v));
            }
            "--suspect-pid-file" => {
                i += 1;
                let v = argv.get(i).ok_or("--suspect-pid-file needs a path")?;
                if suspect_pid_file.is_some() {
                    return Err(
                        "service-attempt-trace takes at most one --suspect-pid-file".to_string()
                    );
                }
                suspect_pid_file = Some(PathBuf::from(v));
            }
            "--" => {
                let rest = argv[i + 1..].to_vec();
                if rest.is_empty() {
                    return Err(
                        "service-attempt-trace needs a suspect command after --".to_string()
                    );
                }
                let log = log.ok_or("--log is required")?;
                return Ok(AttemptTraceArgs {
                    log,
                    suspect_pid_file,
                    argv: rest,
                });
            }
            other => return Err(format!("service-attempt-trace: unknown flag {other:?}")),
        }
        i += 1;
    }
    Err("service-attempt-trace needs -- CMD...".to_string())
}

/// Harness-timeline JSON (harness-written; see `HELP`).
#[derive(Debug, serde::Deserialize)]
struct Timeline {
    harness_pid: i32,
    observer_pid: i32,
    service_pids: Vec<i32>,
    workload: Vec<i32>,
    canary: Vec<i32>,
    quiet_window: (u64, u64),
    sends: Vec<HarnessSend>,
    #[serde(default)]
    external_events: Vec<ExternalEvent>,
}

fn read_witness_log(path: &std::path::Path) -> Result<Vec<WitnessEntry>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read witness log: {e}"))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str::<WitnessEntry>(line)
                .map_err(|e| format!("witness log line {}: {e}", n + 1))?,
        );
    }
    Ok(out)
}

fn read_attempt_log(path: &std::path::Path) -> Result<Vec<AttemptRecord>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read attempt log: {e}"))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str::<AttemptRecord>(line)
                .map_err(|e| format!("attempt log line {}: {e}", n + 1))?,
        );
    }
    Ok(out)
}

fn adjudicate_files_with_attempts(
    log: &std::path::Path,
    timeline: &std::path::Path,
    attempt_log: Option<&std::path::Path>,
) -> Result<ExitCode, String> {
    let witness = read_witness_log(log)?;
    let attempts = match attempt_log {
        Some(p) => read_attempt_log(p)?,
        None => Vec::new(),
    };
    let raw =
        std::fs::read_to_string(timeline).map_err(|e| format!("cannot read timeline: {e}"))?;
    let tl: Timeline =
        serde_json::from_str(&raw).map_err(|e| format!("cannot parse timeline: {e}"))?;
    let workload: HashSet<i32> = tl.workload.into_iter().collect();
    let canary: HashSet<i32> = tl.canary.into_iter().collect();
    let service: HashSet<i32> = tl.service_pids.into_iter().collect();
    let input = OracleInput {
        witness: &witness,
        attempts: &attempts,
        harness_sends: &tl.sends,
        harness_pid: tl.harness_pid,
        observer_pid: tl.observer_pid,
        service_pids: &service,
        workload: &workload,
        canary: &canary,
        quiet_window: tl.quiet_window,
        external_events: &tl.external_events,
    };
    let (verdict, annotated) = adjudicate(&input);
    let (word, detail, code) = match &verdict {
        SignalVerdict::Pass => ("pass", String::new(), 0),
        SignalVerdict::Fail(d) => ("fail", d.clone(), 1),
        SignalVerdict::Void(d) => ("void", d.clone(), 4),
    };
    let out = serde_json::json!({
        "verdict": word,
        "detail": detail,
        "annotated": annotated.len(),
    });
    println!("{}", serde_json::to_string(&out).unwrap_or_default());
    Ok(ExitCode::from(code))
}

pub fn run(argv: &[String]) -> ExitCode {
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return ExitCode::from(0);
    }
    if argv.first().is_some_and(|a| a == "--adjudicate") {
        let mut log: Option<PathBuf> = None;
        let mut timeline: Option<PathBuf> = None;
        let mut attempt_log: Option<PathBuf> = None;
        let mut i = 1;
        while i < argv.len() {
            match argv[i].as_str() {
                "--log" => {
                    i += 1;
                    let Some(v) = argv.get(i) else {
                        return refuse("--log needs a path");
                    };
                    log = Some(PathBuf::from(v));
                }
                "--timeline" => {
                    i += 1;
                    let Some(v) = argv.get(i) else {
                        return refuse("--timeline needs a path");
                    };
                    timeline = Some(PathBuf::from(v));
                }
                "--attempt-log" => {
                    i += 1;
                    let Some(v) = argv.get(i) else {
                        return refuse("--attempt-log needs a path");
                    };
                    attempt_log = Some(PathBuf::from(v));
                }
                other => return refuse(&format!("service-witness: unknown flag {other:?}")),
            }
            i += 1;
        }
        let (Some(log), Some(timeline)) = (log, timeline) else {
            return refuse("--adjudicate needs --log PATH --timeline PATH");
        };
        return adjudicate_files_with_attempts(&log, &timeline, attempt_log.as_deref())
            .unwrap_or_else(|e| refuse(&e));
    }
    match parse_observe(argv) {
        Ok(args) => run_observer(&ObserverConfig {
            pids: args.pids,
            cgroup_procs: args.cgroup_procs,
            log_path: args.log,
            signal_test: args.signal_test,
        }),
        Err(e) => refuse(&e),
    }
}

/// `service-attempt-trace --log PATH [--suspect-pid-file PATH] --
/// CMD...`: supervise a suspect under the kill-family seccomp
/// filter to completion. Exits 0 (log complete), 2 (usage/spawn
/// failure), or 3 (supervision hole — attempt evidence void).
pub fn run_trace(argv: &[String]) -> ExitCode {
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        println!("{TRACE_HELP}");
        return ExitCode::from(0);
    }
    match parse_attempt_trace(argv) {
        Ok(args) => {
            let rc = run_attempt_tracer(&AttemptTracerConfig {
                log_path: args.log,
                suspect_pid_file: args.suspect_pid_file,
                argv: args.argv,
            });
            ExitCode::from(rc as u8)
        }
        Err(e) => {
            crate::report::err_line(&format!("osslscope service-attempt-trace: {e}"));
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn observe_parses_cgroup_and_pids() {
        let args = parse_observe(&argv(&[
            "--log", "w.jsonl", "--cgroup", "/sys/x", "--pid", "9",
        ]))
        .expect("parse");
        assert_eq!(args.log, PathBuf::from("w.jsonl"));
        assert_eq!(
            args.cgroup_procs,
            Some(PathBuf::from("/sys/x/cgroup.procs"))
        );
        assert_eq!(args.pids, vec![9]);
        assert_eq!(args.signal_test, None);
    }

    #[test]
    fn observe_requires_target_and_log() {
        assert!(parse_observe(&argv(&["--cgroup", "/sys/x"])).is_err());
        assert!(parse_observe(&argv(&["--log", "w.jsonl"])).is_err());
        assert!(parse_observe(&argv(&["--log", "w.jsonl", "--nope", "1"])).is_err());
        assert!(parse_observe(&argv(&["--log", "w.jsonl", "--pid", "0"])).is_err());
    }

    #[test]
    fn help_exits_zero() {
        assert_eq!(run(&argv(&["--help"])), ExitCode::from(0));
    }

    fn timeline_json() -> serde_json::Value {
        serde_json::json!({
            "harness_pid": 100, "observer_pid": 200, "service_pids": [300],
            "workload": [11], "canary": [21],
            "quiet_window": [1_000_000u64, 2_000_000u64],
            "sends": [
                {"at_ns": 400u64, "signo": 10, "target_pid": 21, "sender_pid": 100}
            ],
            "external_events": [],
        })
    }

    fn write_temp(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn adjudicate_pass_leg() {
        let dir = std::env::temp_dir().join(format!("witness-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = write_temp(
            &dir,
            "w.jsonl",
            "{\"at_ns\":500,\"signo\":10,\"sender_pid\":100,\"target_pid\":21,\"uncertain\":false,\"kind\":\"delivery\"}\n",
        );
        let tl = write_temp(&dir, "t.json", &timeline_json().to_string());
        let code = adjudicate_files_with_attempts(&log, &tl, None).expect("adjudicate");
        assert_eq!(code, ExitCode::from(0));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn adjudicate_fail_leg_signaling_service() {
        let dir = std::env::temp_dir().join(format!("witness-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Second service lifetime pid 301 signals the workload — ANY
        // lifetime's service-originated signal FAILs. The canary
        // delivery is present (positive control proved) so the
        // verdict reaches the suspect check.
        let log = write_temp(
            &dir,
            "w.jsonl",
            "{\"at_ns\":500,\"signo\":10,\"sender_pid\":100,\"target_pid\":21,\"uncertain\":false,\"kind\":\"delivery\"}\n{\"at_ns\":600,\"signo\":15,\"sender_pid\":301,\"target_pid\":11,\"uncertain\":false,\"kind\":\"delivery\"}\n",
        );
        let mut tl = timeline_json();
        tl["service_pids"] = serde_json::json!([300, 301]);
        let tlp = write_temp(&dir, "t.json", &tl.to_string());
        let code = adjudicate_files_with_attempts(&log, &tlp, None).expect("adjudicate");
        assert_eq!(code, ExitCode::from(1));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn adjudicate_rejects_unreadable_input() {
        let missing = PathBuf::from("/nonexistent-witness-cli/missing.jsonl");
        assert!(adjudicate_files_with_attempts(&missing, &missing, None).is_err());
        assert_eq!(
            run(&argv(&["--adjudicate", "--log", "a"])),
            ExitCode::from(2)
        );
    }

    #[test]
    fn attempt_trace_parses_cmd() {
        let args = parse_attempt_trace(&argv(&[
            "--log",
            "a.jsonl",
            "--suspect-pid-file",
            "s.pid",
            "--",
            "sh",
            "-c",
            "true",
        ]))
        .expect("parse");
        assert_eq!(args.log, PathBuf::from("a.jsonl"));
        assert_eq!(args.suspect_pid_file, Some(PathBuf::from("s.pid")));
        assert_eq!(args.argv, vec!["sh", "-c", "true"]);
    }

    #[test]
    fn attempt_trace_requires_log_separator_and_cmd() {
        assert!(parse_attempt_trace(&argv(&["--", "true"])).is_err());
        assert!(parse_attempt_trace(&argv(&["--log", "a.jsonl", "true"])).is_err());
        assert!(parse_attempt_trace(&argv(&["--log", "a.jsonl", "--"])).is_err());
        assert!(parse_attempt_trace(&argv(&["--log", "a.jsonl", "--nope", "1"])).is_err());
    }

    #[test]
    fn adjudicate_with_attempt_log_leg() {
        // Canary positive control proved (delivery present) while the
        // attempt channel caught a suspect→workload send ⟹ FAIL.
        let dir = std::env::temp_dir().join(format!("witness-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = write_temp(
            &dir,
            "w.jsonl",
            "{\"at_ns\":500,\"signo\":10,\"sender_pid\":100,\"target_pid\":21,\"uncertain\":false,\"kind\":\"delivery\"}\n",
        );
        let attempt_log = write_temp(
            &dir,
            "a.jsonl",
            "{\"at_ns\":600,\"sender_pid\":200,\"sender_comm\":\"osslscope\",\"syscall\":\"kill\",\"syscall_nr\":62,\"target_pid\":11,\"signo\":23,\"result\":0}\n",
        );
        let tl = write_temp(&dir, "t.json", &timeline_json().to_string());
        let code =
            adjudicate_files_with_attempts(&log, &tl, Some(&attempt_log)).expect("adjudicate");
        assert_eq!(code, ExitCode::from(1));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
