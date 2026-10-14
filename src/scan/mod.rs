//! SPDX-License-Identifier: GPL-3.0-or-later
//! Scan-plane host modules (P7 item 3+): the birth registry (item-3
//! subtask E), the per-invocation join oracle (item 4), the
//! governor policy (item 5, host half), and the production backend
//! (integration: drain → join → warm → control over members.o).

pub mod backend;
pub mod governor;
pub mod oracle;
pub mod registry;
