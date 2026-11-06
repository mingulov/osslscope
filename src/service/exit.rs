//! SPDX-License-Identifier: GPL-3.0-or-later
//! §7.3 run exit: ONE truth table over per-window outcomes.
//!
//! Each window's exit is `report::exit_for` with `child_exit = None`
//! (no owned children, §1.1). The process exit folds run-level
//! conditions in the frozen priority order below (first match wins).

use crate::evidence::Completeness;
use crate::policy::PolicyOutcome;

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

/// O(1) run-exit accumulator (R1 finding 2a): the §7.3 fold
/// inputs per window are outcome/status/delivery BITS only — never
/// the document. One struct per RUN (fixed 16 bytes); per-window
/// document clones are unrepresentable here by construction.
#[derive(Debug, Clone, Default)]
pub struct RunFold {
    windows: u64,
    violation: bool,
    fatal_salvaged: bool,
    no_verdict: bool,
    inconclusive: bool,
    incomplete: bool,
    delivery_failed: bool,
}

impl RunFold {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one finalized window's §7.3 inputs (call per window —
    /// O(1) time and heap). `usable` is the window document's
    /// `has_usable_evidence()` (computed by the caller from its
    /// already-held document — never cloned in).
    pub fn add(
        &mut self,
        outcome: PolicyOutcome,
        status: &Completeness,
        usable: bool,
        delivery_failed: bool,
    ) {
        self.windows += 1;
        self.violation |= outcome == PolicyOutcome::Violation;
        self.fatal_salvaged |= matches!(status, Completeness::Fatal { .. }) && usable;
        self.no_verdict |= outcome == PolicyOutcome::NoVerdict;
        self.inconclusive |= outcome == PolicyOutcome::Inconclusive;
        self.incomplete |= !matches!(status, Completeness::Complete);
        self.delivery_failed |= delivery_failed;
    }

    /// Fold finalized windows + run conditions into the process exit.
    ///
    /// Priority (frozen): 10 violation → 1 salvaged Fatal → 4
    /// zero/NoVerdict → 1 delivery/tool → 11 Inconclusive → 3
    /// partial/interrupted → 0 clean.
    pub fn fold(&self, tool_failure: Option<RunToolFailure>, interrupted: bool) -> u8 {
        if self.violation {
            return 10;
        }
        if self.fatal_salvaged {
            return 1;
        }
        if self.windows == 0 || self.no_verdict {
            return 4;
        }
        if tool_failure.is_some() || self.delivery_failed {
            return 1;
        }
        if self.inconclusive {
            return 11;
        }
        if interrupted || self.incomplete {
            return 3;
        }
        0
    }
}
