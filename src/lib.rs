//! SPDX-License-Identifier: GPL-3.0-or-later
//! osslscope — non-interposing OpenSSL observer on eBPF uprobes.
//!
//! Module build order per PLAN §4: P1 owns `cli`, `doctor`, `kinds`,
//! `discovery` + `crates/ossl-discover`. Later phases add attach (P2),
//! semantics (P3), hardening (P4+) — no stub modules until owned.

pub mod aliases;
// T04 (coordinator review): new modules for owned-target custody +
// safe CLI arguments; placement is alphabetical, no other movement.
pub mod args;
pub mod capture;
pub mod check;
pub mod cli;
pub mod discovery;
pub mod doctor;
pub mod inspect;
pub mod kinds;
pub mod loader;
pub mod pin;
pub mod plan;
pub mod report;
pub mod schema;
pub mod target;
