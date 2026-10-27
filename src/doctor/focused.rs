// SPDX-License-Identifier: GPL-3.0-or-later
//! Scanner-owned functional controls for the ordinary focused workflow.
use super::{
    insns_noop, insns_probe_read_user, is_perm_errno, run_map_create, run_multi_self, run_prog_load,
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Available,
    Denied,
    Unavailable,
    NotChecked,
}
fn state(probe: super::ProbeOut) -> State {
    if probe.ok {
        State::Available
    } else if is_perm_errno(probe.errno) {
        State::Denied
    } else {
        State::Unavailable
    }
}
const USAGE: &str = "usage: osslscope doctor [--json | --format human|json] [--observation-object PATH] [--count-object PATH]\nChecks scanner-owned inventory, namespace, companion integrity and functional BPF load/self-attachment. Target access remains scope dependent.\n  --libcrypto PATH selects legacy profile diagnostics.\n  --discovery preserves discovery-only capability checks.";
pub(crate) fn run(args: &[String]) -> ExitCode {
    let mut json = false;
    let mut format_seen = false;
    let mut observation: Option<PathBuf> = None;
    let mut count: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" if args.len() == 1 => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--json" if !format_seen => {
                json = true;
                format_seen = true;
            }
            "--format" if !format_seen => {
                match it.next().map(String::as_str) {
                    Some("json") => json = true,
                    Some("human") => (),
                    _ => return usage(),
                }
                format_seen = true;
            }
            "--observation-object" if observation.is_none() => match it.next() {
                Some(v) => observation = Some(v.into()),
                None => return usage(),
            },
            "--count-object" if count.is_none() => match it.next() {
                Some(v) => count = Some(v.into()),
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    let objects = match crate::package::commands::resolve_focused_objects(
        observation.as_deref(),
        count.as_deref(),
    ) {
        Ok(objects) => objects,
        Err(_) => {
            crate::report::err_line("osslscope doctor: invalid companion");
            return ExitCode::from(2);
        }
    };
    let observation_companion = if objects.observation.is_empty() {
        State::Unavailable
    } else {
        State::Available
    };
    let count_companion = if objects.count.is_empty() {
        State::Unavailable
    } else {
        State::Available
    };
    let inventory = match crate::inventory::scope::ScopedScanner::new(
        crate::inventory::scope::Selection {
            pids: vec![std::process::id()],
            ..Default::default()
        },
        crate::inventory::Limits {
            max_pids: 1,
            ..Default::default()
        },
    ) {
        Ok(mut scanner) => {
            if scanner
                .snapshot()
                .processes
                .iter()
                .any(|p| p.pid == std::process::id())
            {
                State::Available
            } else {
                State::Unavailable
            }
        }
        _ => State::Unavailable,
    };
    // Native namespace FD identity, consumed by the same self-count admission
    // as focused capture. No target namespace changes or injected workload.
    let namespace = crate::focused_capture::observer_namespace();
    let pid_namespace = if namespace.is_ok() {
        State::Available
    } else {
        State::Unavailable
    };
    let bpf = state(run_prog_load(&insns_noop()));
    let (user_read, ring_buffer, uprobe_multi) = if matches!(bpf, State::Available) {
        (
            state(run_prog_load(&insns_probe_read_user())),
            state(run_map_create(27, 0, 0, 1 << 20)),
            state(run_multi_self()),
        )
    } else {
        (State::NotChecked, State::NotChecked, State::NotChecked)
    };
    let observation_load = if objects.observation.is_empty() {
        State::NotChecked
    } else {
        match crate::provider_observation::ProviderSession::open(
            crate::provider_observation::ObservationLimits::default(),
            &objects.observation,
        ) {
            Ok(session) => {
                drop(session);
                State::Available
            }
            Err(_) => State::Unavailable,
        }
    };
    let count_load = if objects.count.is_empty() {
        State::NotChecked
    } else if let Ok(namespace) = namespace {
        match crate::focused_count::FocusedCounter::open(
            &objects.count,
            std::process::id(),
            namespace,
            crate::focused_count::CountLimits {
                window: crate::evidence::CountAdmissionWindow {
                    start_ns: 1,
                    deadline_ns: u64::MAX,
                },
                ..Default::default()
            },
        ) {
            Ok(counter) => {
                drop(counter);
                State::Available
            }
            Err(_) => State::Unavailable,
        }
    } else {
        State::NotChecked
    };
    let states = [
        ("inventory", inventory),
        ("observation_companion", observation_companion),
        ("count_companion", count_companion),
        ("pid_namespace", pid_namespace),
        ("bpf", bpf),
        ("user_read", user_read),
        ("ring_buffer", ring_buffer),
        ("uprobe_multi", uprobe_multi),
        ("observation_load", observation_load),
        ("count_load", count_load),
    ];
    let available = states.iter().all(|(_, s)| matches!(s, State::Available));
    let capabilities: std::collections::BTreeMap<_, _> = states.into_iter().collect();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let rendered = (|| -> io::Result<()> {
        if json {
            serde_json::to_writer(&mut out, &serde_json::json!({"schema_version": "osslscope.focused.doctor.v1", "record": "doctor", "capabilities": capabilities, "historical_activation": "unknown", "execution": "not_observed"})).map_err(io::Error::other)?;
            out.write_all(b"\n")?;
        } else {
            out.write_all(
                b"Focused capability checks; target access/attachment remains scope dependent.\n",
            )?;
            for (name, value) in capabilities {
                write!(out, "  {name}=")?;
                serde_json::to_writer(&mut out, &value).map_err(io::Error::other)?;
                out.write_all(b"\n")?;
            }
            out.write_all(b"  historical_activation=unknown execution=not_observed\n")?;
        }
        out.flush()
    })();
    ExitCode::from(if rendered.is_err() {
        1
    } else if available {
        0
    } else {
        3
    })
}
fn usage() -> ExitCode {
    crate::report::err_line(USAGE);
    ExitCode::from(2)
}
