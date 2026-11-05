//! SPDX-License-Identifier: GPL-3.0-or-later
//! 6B bounded service: windows, reload, durability, sinks.
//!
//! Implements the frozen 6B D-record
//! (`docs/2026-11-04-t7-6b-d-record.md`) plus the eight carried T7.3
//! rulings (L1-L6, MEM, MAXGATE). Layout mirrors the D-record
//! sections: `cli` (§1), `coordinator` (§2 windows), `policy`
//! reload (§3, in `coordinator` + `state`), `state` + `publish` +
//! `recovery` (§4), `account` + `queue` + `stream` (§5),
//! `retain` (§6), `worker` + `signals` (§7), `exit` (§7.3),
//! `envelope` (§§10-11 shapes), `snapshot` (§11.1 producer),
//! `witness` (L5 observer + §9 signal evidence).

pub mod account;
pub mod cli;
pub mod coordinator;
pub mod envelope;
pub mod exit;
pub mod publish;
pub mod queue;
pub mod recovery;
pub mod retain;
pub mod signals;
pub mod snapshot;
pub mod staging;
pub mod state;
pub mod stream;
pub mod witness;
pub mod witness_cli;
pub mod worker;

use std::process::ExitCode;

/// `osslscope service` entry: parse, admit, run, exit per §7.3.
pub fn run(args: &[String]) -> ExitCode {
    coordinator::run(args)
}
