//! SPDX-License-Identifier: GPL-3.0-or-later
//! osslscope — non-interposing OpenSSL observer on eBPF uprobes.
//!
//! Module build order per PLAN §4: P1 owns `cli`, `doctor`, `kinds`,
//! `discovery` + `crates/ossl-discover`. Later phases add attach (P2),
//! semantics (P3), hardening (P4+) — no stub modules until owned.

pub mod aliases;
pub mod capture;
pub mod check;
pub mod cli;
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
