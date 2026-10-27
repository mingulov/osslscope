//! SPDX-License-Identifier: GPL-3.0-or-later
//! osslscope — non-interposing OpenSSL observer on eBPF uprobes.
//!
//! Discovery, capture, policy and reporting are implemented by the modules
//! below. The current report/check path uses the finalized v2 evidence
//! document; live and release qualification remain separate.

pub mod aliases;
// T04 (coordinator review): new modules for owned-target custody +
// safe CLI arguments; placement is alphabetical, no other movement.
pub mod args;
pub mod capture;
pub(crate) mod capture_setup;
pub mod check;
pub mod cli;
pub(crate) mod count_owner;
// T07: immutable planner identity + count session (coordinator review).
pub mod count_session;
pub mod discovery;
pub mod doctor;
// T01 (coordinator review): conserved evidence model + pure policy primitives.
pub mod evidence;
pub mod inspect;
pub mod inventory;
pub mod kinds;
pub mod lifecycle_producer;
pub mod loader;
pub mod package;
pub mod pin;
pub mod plan;
// T01 (coordinator review): pure policy predicate primitives, no CLI wiring.
pub mod policy;
pub(crate) mod policy_config;
pub(crate) mod profile;
pub mod provider_observation;
pub mod report;
// R19 (P7 item 3): scan-plane birth registry, join oracle, governor
// and production backend (see scan's module documentation).
pub mod scan;
pub mod schema;
pub mod target;

pub mod focused_count;
