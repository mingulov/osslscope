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
// T07: immutable planner identity + count session (coordinator review).
pub mod count_session;
pub mod discovery;
pub mod doctor;
// T01 (coordinator review): conserved evidence model + pure policy primitives.
pub mod evidence;
pub mod inspect;
pub mod kinds;
pub mod loader;
pub mod pin;
pub mod plan;
// T01 (coordinator review): pure policy predicate primitives, no CLI wiring.
pub mod policy;
pub mod report;
pub mod schema;
pub mod target;
