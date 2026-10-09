//! SPDX-License-Identifier: GPL-3.0-or-later
//! T01 pure policy predicate primitives (spec R06).
//!
//! No CLI wiring: these are total functions over
//! [`crate::evidence`] types. CLI parsing, exit mapping and artifact
//! delivery belong to T10/T11. Ambiguity inside one alias list (mixed
//! or unresolved algorithm classes) and ambiguity between candidates
//! (mixed per-candidate outcomes in `match_bounds`) both shape
//! definite/possible bounds; there is no boolean-first-alias shortcut.

use crate::evidence::{CandidateIdentity, MatchBounds, PredicateMatch, RuleVerdict};

/// Classification bucket for unknown, aliased, overlong or unreadable
/// algorithm input. A candidate carrying this class can prove neither
/// an algorithm match nor an algorithm absence.
pub const UNRESOLVED_ALGORITHM_CLASS: &str = "other";

/// Pure predicate over one candidate identity. Algorithm predicates
/// are three-valued over the candidate's whole class list; provider,
/// operation and weak-alias predicates are certain even when the
/// algorithm alone is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Algorithm(String),
    ProviderClass(String),
    ProviderObject(String),
    Op(u32),
    FuncId(u32),
    WeakAlias,
    Not(Box<Predicate>),
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
}

impl Predicate {
    /// Evaluate against one candidate. `Algorithm` is `Yes` only when
    /// every recognized class equals the target, `No` only when none
    /// does and none is unresolved; mixed lists, empty lists and lists
    /// containing [`UNRESOLVED_ALGORITHM_CLASS`] are `Unknown`.
    pub fn eval(&self, c: &CandidateIdentity) -> PredicateMatch {
        match self {
            Predicate::Algorithm(want) => {
                if c.algorithm_classes.is_empty() {
                    return PredicateMatch::Unknown;
                }
                if c.algorithm_classes
                    .iter()
                    .any(|a| a == UNRESOLVED_ALGORITHM_CLASS)
                {
                    return PredicateMatch::Unknown;
                }
                let matching = c.algorithm_classes.iter().filter(|a| *a == want).count();
                if matching == c.algorithm_classes.len() {
                    PredicateMatch::Yes
                } else if matching == 0 {
                    PredicateMatch::No
                } else {
                    PredicateMatch::Unknown
                }
            }
            Predicate::ProviderClass(want) => {
                if &c.provider_class == want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::ProviderObject(want) => {
                if &c.provider.0 == want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::Op(want) => {
                if c.op == *want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::FuncId(want) => {
                if c.funcid == *want {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::WeakAlias => {
                if c.weak_alias {
                    PredicateMatch::Yes
                } else {
                    PredicateMatch::No
                }
            }
            Predicate::Not(inner) => match inner.eval(c) {
                PredicateMatch::Yes => PredicateMatch::No,
                PredicateMatch::No => PredicateMatch::Yes,
                PredicateMatch::Unknown => PredicateMatch::Unknown,
            },
            Predicate::All(parts) => {
                let mut out = PredicateMatch::Yes;
                for p in parts {
                    match p.eval(c) {
                        PredicateMatch::No => return PredicateMatch::No,
                        PredicateMatch::Unknown => out = PredicateMatch::Unknown,
                        PredicateMatch::Yes => {}
                    }
                }
                out
            }
            Predicate::Any(parts) => {
                let mut out = PredicateMatch::No;
                for p in parts {
                    match p.eval(c) {
                        PredicateMatch::Yes => return PredicateMatch::Yes,
                        PredicateMatch::Unknown => out = PredicateMatch::Unknown,
                        PredicateMatch::No => {}
                    }
                }
                out
            }
        }
    }

    /// Adapter for `crate::evidence::match_bounds`.
    pub fn as_fn(&self) -> impl Fn(&CandidateIdentity) -> PredicateMatch + '_ {
        |c| self.eval(c)
    }
}

/// One policy rule. Rules are ANDed by the caller; `--require-provider`
/// stays existential (at least one definite execution of that class).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Require(Predicate),
    Deny(Predicate),
}

/// Require-X over conserved bounds with explicit relevant completeness
/// (complete relevant coverage and candidates, as decided by the
/// caller): definite use passes; clean absence in a complete window
/// violates; possible or unknown use, or incomplete relevance, is
/// inconclusive — the requirement is unproven, never fabricated.
pub fn evaluate_require(bounds: &MatchBounds, relevant_complete: bool) -> RuleVerdict {
    if bounds.definite > 0 {
        RuleVerdict::Pass
    } else if relevant_complete && bounds.possible == Some(0) {
        RuleVerdict::Violation
    } else {
        RuleVerdict::Inconclusive
    }
}

/// Deny-X over conserved bounds: definite use violates; clean absence
/// in a complete window passes; possible or unknown use, or incomplete
/// relevance, is inconclusive — never a definite violation from an
/// ambiguous candidate.
pub fn evaluate_deny(bounds: &MatchBounds, relevant_complete: bool) -> RuleVerdict {
    if bounds.definite > 0 {
        RuleVerdict::Violation
    } else if relevant_complete && bounds.possible == Some(0) {
        RuleVerdict::Pass
    } else {
        RuleVerdict::Inconclusive
    }
}

/// Evaluate one rule over conserved bounds.
pub fn evaluate_rule(rule: &Rule, bounds: &MatchBounds, relevant_complete: bool) -> RuleVerdict {
    match rule {
        Rule::Require(_) => evaluate_require(bounds, relevant_complete),
        Rule::Deny(_) => evaluate_deny(bounds, relevant_complete),
    }
}
