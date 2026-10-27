//! SPDX-License-Identifier: GPL-3.0-or-later
//! Dispatch discovery (P1). Promoted from `spike/src/bin/harvest.rs`
//! (P0-4): two-stage provider-table harvest — init-return walk finds
//! `query_operation` (funcid 1027), query-return walks hand back one ROW
//! event per (op, alg, funcid, addr), and the relocation leg re-bases
//! every row to file offsets via `/proc/pid/maps` + disk-ELF checks.
//!
//! Mechanism note (P0-10 ladder): the live attach leg below still uses
//! aya single-probe attach, which needs `+CAP_SYS_ADMIN` for the perf
//! path while multi-link attach needs only the BPF pair. P1 either
//! migrates harvest to multi-link or documents admin for discovery;
//! the relocation + schema legs are mechanism-independent either way.

pub mod builtin;
pub(crate) mod classifier_maps;
pub mod coverage;
pub mod elf;
pub mod flavor;
pub mod harvest;
pub mod legacy;
pub mod maps;
pub mod onboard;
pub mod provider;
pub mod schema;
pub mod session;

pub(crate) use classifier_maps::{ClassifierRole, initialize_classifier_maps};
