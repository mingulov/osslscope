// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded sampled inventory, not a lossless event or execution history.
use super::{
    CaptureInterval, GapReason, Limits, ModuleRecord, Snapshot,
    scope::{ScopedScanner, Selection},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct WatchOptions {
    pub selection: Selection,
    pub limits: Limits,
    pub interval: Duration,
    pub duration: Option<Duration>,
}
impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            selection: Selection::default(),
            limits: Limits::default(),
            interval: Duration::from_secs(1),
            duration: None,
        }
    }
}
impl WatchOptions {
    pub fn validate(&self) -> io::Result<()> {
        if !(Duration::from_millis(50)..=Duration::from_secs(3600)).contains(&self.interval)
            || self
                .duration
                .is_some_and(|d| d.is_zero() || d > Duration::from_secs(3600))
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Duration,
    Interrupted,
    ScopeUnavailable,
    Output,
}
#[derive(Clone, Debug, Serialize)]
pub struct WatchOutcome {
    pub schema_version: &'static str,
    pub mode: &'static str,
    pub record: &'static str,
    pub sequence: u64,
    pub reason: EndReason,
    pub status: u8,
    pub elapsed: Duration,
    pub limits: Limits,
    pub gap: Option<GapReason>,
    pub sampled_history: &'static str,
}
impl WatchOutcome {
    pub fn exit_code(&self) -> u8 {
        self.status
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ChangeKind {
    ProcessSeen,
    ModuleSeen,
    ProcessNotSeen,
    ModuleNotSeen,
    VisibilityLost,
}
#[derive(Serialize)]
struct Change {
    kind: ChangeKind,
    pid: u32,
    starttime: u64,
    module: Option<ModuleRecord>,
}
#[derive(Serialize)]
struct Record<'a> {
    schema_version: &'static str,
    mode: &'static str,
    record: &'static str,
    sequence: u64,
    interval: &'a CaptureInterval,
    poll_interval: Duration,
    snapshot: &'a Snapshot,
    changes: Vec<Change>,
    sampled_history: &'static str,
}
fn same_module(a: &ModuleRecord, b: &ModuleRecord) -> bool {
    (a.info.device, a.info.inode, &a.info.sha256) == (b.info.device, b.info.inode, &b.info.sha256)
}
fn visible(snapshot: &Snapshot, pid: u32) -> bool {
    snapshot.gaps.iter().all(|gap| {
        if gap.pid.is_some_and(|value| value != pid) {
            return true;
        }
        // Candidate association is still uncertain, but successful executable
        // mapping enumeration is usable for sampled absence. Ordinary ELF
        // candidates may be filtered from the public module list. Every
        // backing/read/churn/selection failure still forbids absence claims.
        // IdentityUnverified is emitted only after successful candidate
        // acquisition; unresolved/mismatched backing is BackingUnavailable.
        gap.reason == GapReason::IdentityUnverified
    })
}
fn changes(previous: Option<&Snapshot>, current: &Snapshot) -> Vec<Change> {
    let mut result = Vec::new();
    let mut add = |kind, pid, starttime, module| {
        result.push(Change {
            kind,
            pid,
            starttime,
            module,
        })
    };
    for process in &current.processes {
        let old = previous.and_then(|s| {
            s.processes.iter().find(|p| {
                p.pid == process.pid
                    && p.starttime == process.starttime
                    && p.namespaces == process.namespaces
            })
        });
        if old.is_none() {
            add(
                ChangeKind::ProcessSeen,
                process.pid,
                process.starttime,
                None,
            );
        }
        for module in &process.modules {
            if old.is_none_or(|p| !p.modules.iter().any(|m| same_module(m, module))) {
                add(
                    ChangeKind::ModuleSeen,
                    process.pid,
                    process.starttime,
                    Some(module.clone()),
                );
            }
        }
    }
    if let Some(previous) = previous {
        for old in &previous.processes {
            let now = current.processes.iter().find(|p| {
                p.pid == old.pid && p.starttime == old.starttime && p.namespaces == old.namespaces
            });
            if !visible(current, old.pid) {
                add(ChangeKind::VisibilityLost, old.pid, old.starttime, None);
            } else if let Some(now) = now {
                for module in &old.modules {
                    if !now.modules.iter().any(|m| same_module(m, module)) {
                        add(
                            ChangeKind::ModuleNotSeen,
                            old.pid,
                            old.starttime,
                            Some(module.clone()),
                        );
                    }
                }
            } else if !current.processes.iter().any(|p| p.pid == old.pid) {
                add(ChangeKind::ProcessNotSeen, old.pid, old.starttime, None);
            } else {
                // Reused PID or changed namespace is a new observation, not
                // evidence of an exit or unload of the previous incarnation.
                add(ChangeKind::VisibilityLost, old.pid, old.starttime, None);
            }
        }
    }
    result
}
fn emit(value: &impl Serialize, writer: &mut impl Write, human: bool) -> io::Result<()> {
    if human {
        // Finite enums and safe numeric/hash identities only. This is one
        // transient bounded record, never a retained history array.
        let value = serde_json::to_value(value).map_err(io::Error::other)?;
        if value["record"] == "end" {
            writeln!(
                writer,
                "Watch ended: {} (status {}, snapshots {}). Sampled history remains incomplete.",
                value["reason"], value["status"], value["sequence"]
            )?;
            writeln!(
                writer,
                "  elapsed={}s+{}ns; limits: pids={} objects={} charged_bytes={} timeout={}s+{}ns",
                value["elapsed"]["secs"],
                value["elapsed"]["nanos"],
                value["limits"]["max_pids"],
                value["limits"]["max_objects"],
                value["limits"]["max_read_bytes"],
                value["limits"]["timeout"]["secs"],
                value["limits"]["timeout"]["nanos"]
            )?;
            if !value["gap"].is_null() {
                writeln!(writer, "  scope gap={}", value["gap"])?;
            }
        } else {
            writeln!(
                writer,
                "Snapshot {}: inventory {}; sampled changes {}",
                value["sequence"],
                value["snapshot"]["capabilities"]["inventory"],
                value["changes"].as_array().map_or(0, Vec::len)
            )?;
            for gap in value["snapshot"]["gaps"].as_array().into_iter().flatten() {
                writeln!(writer, "  gap={} pid={}", gap["reason"], gap["pid"])?;
            }
            for change in value["changes"].as_array().into_iter().flatten() {
                write!(
                    writer,
                    "  {} pid={} starttime={}",
                    change["kind"], change["pid"], change["starttime"]
                )?;
                if !change["module"].is_null() {
                    write!(writer, " sha256={}", change["module"]["info"]["sha256"])?;
                }
                writeln!(writer)?;
            }
        }
    } else {
        serde_json::to_writer(&mut *writer, value).map_err(io::Error::other)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}
/// Stream bounded NDJSON. This never installs signal handlers or signals a
/// workload. Cancellation/deadlines are cooperative between bounded snapshots.
pub fn run(
    options: &WatchOptions,
    writer: &mut impl Write,
    cancel: &AtomicBool,
) -> Result<WatchOutcome, io::Error> {
    run_formatted(options, writer, cancel, false)
}
pub(super) fn run_formatted(
    options: &WatchOptions,
    writer: &mut impl Write,
    cancel: &AtomicBool,
    human: bool,
) -> io::Result<WatchOutcome> {
    options.validate()?;
    let started = Instant::now();
    if human {
        writer.write_all(b"Passive sampled inventory: mappings do not prove activation or execution.\nProvider activation/interfaces: unknown; execution: not_observed.\n")?;
    }
    let mut sequence = 0;
    let mut status = 4;
    let mut previous = None;
    let mut end = WatchOutcome {
        schema_version: "osslscope.discovery.v1",
        mode: "watch",
        record: "end",
        sequence: 0,
        reason: EndReason::Duration,
        status,
        elapsed: Duration::ZERO,
        limits: options.limits.clone(),
        gap: None,
        sampled_history: "incomplete",
    };
    if cancel.load(Ordering::Relaxed) {
        end.reason = EndReason::Interrupted;
        end.status = 3;
        end.elapsed = started.elapsed();
        emit(&end, writer, human)?;
        return Ok(end);
    }
    let mut scanner = match ScopedScanner::new(options.selection.clone(), options.limits.clone()) {
        Ok(scanner) => scanner,
        Err(gap) => {
            if cancel.load(Ordering::Relaxed) {
                end.reason = EndReason::Interrupted;
                end.status = 3;
            } else {
                end.reason = EndReason::ScopeUnavailable;
            }
            end.gap = Some(gap);
            end.elapsed = started.elapsed();
            emit(&end, writer, human)?;
            return Ok(end);
        }
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            end.reason = EndReason::Interrupted;
            status = 3;
            break;
        }
        if options.duration.is_some_and(|d| started.elapsed() >= d) {
            break;
        }
        let poll_started = Instant::now();
        let snapshot = match options.duration {
            Some(duration) => scanner.snapshot_for(duration.saturating_sub(started.elapsed())),
            None => scanner.snapshot(),
        };
        sequence += 1;
        status = snapshot.exit_code();
        let record = Record {
            schema_version: "osslscope.discovery.v1",
            mode: "watch",
            record: "snapshot",
            sequence,
            interval: &snapshot.interval,
            poll_interval: options.interval,
            changes: changes(previous.as_ref(), &snapshot),
            snapshot: &snapshot,
            sampled_history: "incomplete",
        };
        if let Err(error) = emit(&record, writer, human) {
            end.reason = EndReason::Output;
            end.status = 1;
            end.sequence = sequence;
            end.elapsed = started.elapsed();
            // A broken sink often cannot accept its end record. Attempt once;
            // preserve the original error and never continue acquiring data.
            let _ = emit(&end, writer, human);
            return Err(error);
        }
        previous = Some(snapshot);
        let wait_started = poll_started;
        while wait_started.elapsed() < options.interval {
            if cancel.load(Ordering::Relaxed)
                || options.duration.is_some_and(|d| started.elapsed() >= d)
            {
                break;
            }
            let mut wait = options
                .interval
                .saturating_sub(wait_started.elapsed())
                .min(Duration::from_millis(25));
            if let Some(duration) = options.duration {
                wait = wait.min(duration.saturating_sub(started.elapsed()));
            }
            std::thread::sleep(wait);
        }
    }
    end.sequence = sequence;
    end.status = status;
    end.elapsed = started.elapsed();
    emit(&end, writer, human)?;
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            assert!(self.0.wait().unwrap().success());
        }
    }

    // Catches treating duration-skipped live PIDs as absent, while preserving
    // successful sampled scope departure as process_not_seen.
    #[test]
    fn duration_capped_snapshot_loses_visibility_for_all_live_pids() {
        let mut children: Vec<_> = (0..3)
            .map(|_| {
                Owned(
                    Command::new("/bin/cat")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .spawn()
                        .unwrap(),
                )
            })
            .collect();
        let pids: Vec<_> = children.iter().map(|child| child.0.id()).collect();
        let mut scanner = ScopedScanner::new(
            Selection {
                pids: pids.clone(),
                ..Default::default()
            },
            Limits::default(),
        )
        .unwrap();
        let previous = scanner.snapshot();
        assert_eq!(previous.processes.len(), pids.len());

        // This is the production final-duration snapshot route, with no
        // remaining acquisition budget rather than a host-specific deadline.
        let current = scanner.snapshot_for(Duration::ZERO);
        assert!(current.processes.is_empty());
        let observed = serde_json::to_value(changes(Some(&previous), &current)).unwrap();
        let observed = observed.as_array().unwrap();
        assert_eq!(observed.len(), pids.len());
        for &pid in &pids {
            assert!(
                observed
                    .iter()
                    .any(|change| { change["pid"] == pid && change["kind"] == "visibility_lost" })
            );
        }

        // A successful scan of a smaller selection can still report a sampled
        // departure for the omitted live processes.
        let mut remaining = ScopedScanner::new(
            Selection {
                pids: vec![pids[0]],
                ..Default::default()
            },
            Limits::default(),
        )
        .unwrap();
        let current = remaining.snapshot();
        assert_eq!(current.processes.len(), 1);
        assert!(visible(&current, pids[1]));
        assert!(visible(&current, pids[2]));
        let observed = serde_json::to_value(changes(Some(&previous), &current)).unwrap();
        for &pid in &pids[1..] {
            let matching: Vec<_> = observed
                .as_array()
                .unwrap()
                .iter()
                .filter(|change| change["pid"] == pid)
                .collect();
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0]["kind"], "process_not_seen");
        }
        for child in &mut children {
            assert!(child.0.try_wait().unwrap().is_none());
        }
    }
}
