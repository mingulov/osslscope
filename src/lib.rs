//! osslscope — non-interposing OpenSSL observer on eBPF uprobes.
//!
//! Module build order per PLAN §4: P1 owns `cli`, `doctor`, `kinds`,
//! `discovery` + `crates/ossl-discover`. Later phases add attach (P2),
//! semantics (P3), hardening (P4+) — no stub modules until owned.

pub mod aliases;
pub mod cli;
pub mod discovery;
pub mod doctor;
pub mod inspect;
pub mod kinds;
