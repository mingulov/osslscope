//! SPDX-License-Identifier: GPL-3.0-or-later
//! Scan-plane host modules (P7 item 3+): the birth registry (item-3
//! subtask E), the per-invocation join oracle (item 4), and the
//! governor policy (item 5, host half). The harness drives the
//! registry explicitly; the daemon 100ms-loop integration is item 5.

pub mod governor;
pub mod oracle;
pub mod registry;
