//! SPDX-License-Identifier: GPL-3.0-or-later
//! §7.3 run exit: ONE truth table over per-window outcomes.
//!
//! Each window's exit is `report::exit_for` with `child_exit = None`
//! (no owned children, §1.1). The process exit folds run-level
//! conditions in the frozen priority order below (first match wins).

use crate::evidence::{CaptureDocument, Completeness};
use crate::policy::PolicyOutcome;
use crate::report::DeliveryResult;

/// Run-level tool failures (frozen, priority-4 1-group). Each is
/// also named at its site; presence here only feeds the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunToolFailure {
    /// Post-open sink-identity mismatch (§4.1).
    SinkIdentity,
    /// Sequence-exhaustion refusal (§4.2).
    SequenceExhausted,
    /// Held rotated-name collision (§6.1).
    RotatedNameHeld,
    /// State-commit failure after publish (§4.3 step 5).
    StateCommit,
    /// DIR-publish `worker_unavailable` abandonment (§7.2).
    WorkerUnavailable,
    /// `deletion_failure` quota-stop (§6.2).
    QuotaDeletionFailure,
    /// UNCERTAIN publish (link landed, dir entry unproven, §4.2).
    /// The §4.2 exit sentence ("exits as a run-level tool failure,
    /// §7.3 priority 4") forces a priority-4 trigger the six named
    /// sites do not cover (the window is finalized into NEITHER
    /// the windows list NOR abandonment — T7.4's gap-fill, reported).
    DurabilityUncertain,
}

/// One finalized window's contribution to the exit fold.
#[derive(Debug, Clone)]
pub struct WindowExit {
    /// The window's policy outcome (evaluated, or the `report`-path
    /// map when observe-only).
    pub outcome: PolicyOutcome,
    /// The window document (status + usable-evidence distinction).
    pub doc: CaptureDocument,
    /// The DIR write result for this window.
    pub delivery: DeliveryResult,
}

/// Fold finalized windows + run conditions into the process exit.
///
/// Priority (frozen): 10 violation → 1 salvaged Fatal → 4
/// zero/NoVerdict → 1 delivery/tool → 11 Inconclusive → 3
/// partial/interrupted → 0 clean.
pub fn fold(windows: &[WindowExit], tool_failure: Option<RunToolFailure>, interrupted: bool) -> u8 {
    if windows
        .iter()
        .any(|w| w.outcome == PolicyOutcome::Violation)
    {
        return 10;
    }
    if windows
        .iter()
        .any(|w| matches!(&w.doc.status, Completeness::Fatal { .. }) && w.doc.has_usable_evidence())
    {
        return 1;
    }
    if windows.is_empty()
        || windows
            .iter()
            .any(|w| w.outcome == PolicyOutcome::NoVerdict)
    {
        return 4;
    }
    if tool_failure.is_some() || windows.iter().any(|w| w.delivery.failed()) {
        return 1;
    }
    if windows
        .iter()
        .any(|w| w.outcome == PolicyOutcome::Inconclusive)
    {
        return 11;
    }
    if interrupted
        || windows
            .iter()
            .any(|w| !matches!(&w.doc.status, Completeness::Complete))
    {
        return 3;
    }
    0
}

/// Per-window exit via `report::exit_for` (`child_exit = None`).
pub fn window_exit(w: &WindowExit) -> u8 {
    crate::report::exit_for(w.outcome, None, &w.doc, &w.delivery)
}
