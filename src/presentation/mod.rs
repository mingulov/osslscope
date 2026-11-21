// SPDX-License-Identifier: GPL-3.0-or-later
//! 6C operator presentation (T8.2b): presentation snapshot (§6C-1),
//! Prometheus exposition (§6C-6), OTel mapping (§6C-7), terminal
//! watch (§6C-9/§6C-10), and the `export` command.
pub mod budget;
pub mod export;
pub mod labels;
pub mod otel;
pub mod prometheus;
pub mod snapshot;
pub mod watch;

pub use snapshot::{OperatorSnapshot, Presenter, SCHEMA as PRESENTATION_SCHEMA};
